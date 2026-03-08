import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.56.1";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ScanResult {
  hash: string;
  hash_type: string;
  is_malicious: boolean;
  malware_family: string | null;
  malware_type: string | null;
  threat_level: string | null;
  description: string | null;
  first_seen: string | null;
  detection_count: number;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { hash, hash_type = 'auto' } = await req.json();

    if (!hash) {
      return new Response(
        JSON.stringify({ error: 'Hash is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Validate and detect hash type
    const detectedHashType = detectHashType(hash, hash_type);
    if (!detectedHashType) {
      return new Response(
        JSON.stringify({ error: 'Invalid hash format. Supported: MD5, SHA1, SHA256' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Search for hash in malware signatures database
    let query = supabase.from('malware_signatures').select('*');
    
    switch (detectedHashType) {
      case 'md5':
        query = query.eq('hash_md5', hash.toLowerCase());
        break;
      case 'sha1':
        query = query.eq('hash_sha1', hash.toLowerCase());
        break;
      case 'sha256':
        query = query.eq('hash_sha256', hash.toLowerCase());
        break;
    }

    const { data: signatures, error } = await query;

    if (error) {
      console.error('Database query error:', error);
      throw error;
    }

    const signature = signatures?.[0];

    if (signature) {
      // Update detection count
      await supabase
        .from('malware_signatures')
        .update({ 
          detection_count: (signature.detection_count || 0) + 1,
          last_seen: new Date().toISOString()
        })
        .eq('id', signature.id);

      console.log(`Malware detected: ${signature.malware_family} (${signature.malware_type})`);

      const result: ScanResult = {
        hash: hash.toLowerCase(),
        hash_type: detectedHashType,
        is_malicious: true,
        malware_family: signature.malware_family,
        malware_type: signature.malware_type,
        threat_level: signature.threat_level,
        description: signature.description,
        first_seen: signature.first_seen,
        detection_count: (signature.detection_count || 0) + 1
      };

      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Hash not found - clean
    console.log(`Hash ${hash} not found in malware database - considered clean`);
    const result: ScanResult = {
      hash: hash.toLowerCase(),
      hash_type: detectedHashType,
      is_malicious: false,
      malware_family: null,
      malware_type: null,
      threat_level: null,
      description: null,
      first_seen: null,
      detection_count: 0
    };

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Error in scan-file-hash:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

function detectHashType(hash: string, specifiedType: string): string | null {
  const cleanHash = hash.trim().toLowerCase();
  
  if (specifiedType !== 'auto') {
    const validTypes = ['md5', 'sha1', 'sha256'];
    if (validTypes.includes(specifiedType.toLowerCase())) {
      return specifiedType.toLowerCase();
    }
  }

  // Auto-detect based on length
  if (/^[a-f0-9]{32}$/i.test(cleanHash)) {
    return 'md5';
  } else if (/^[a-f0-9]{40}$/i.test(cleanHash)) {
    return 'sha1';
  } else if (/^[a-f0-9]{64}$/i.test(cleanHash)) {
    return 'sha256';
  }

  return null;
}
