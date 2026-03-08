// Dataset Parsers for CICIDS2017 and UNSW-NB15 formats

export interface ParsedRecord {
  features: Record<string, number>;
  label: string;
  attackCategory?: string;
  rawData: Record<string, string | number>;
}

export interface DatasetInfo {
  name: string;
  format: 'CICIDS2017' | 'UNSW-NB15' | 'KDD99' | 'CUSTOM';
  totalRecords: number;
  featuresCount: number;
  featureNames: string[];
  labelDistribution: Record<string, number>;
  attackCategories: string[];
}

// CICIDS2017 feature columns
export const CICIDS2017_FEATURES = [
  'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
  'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
  'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
  'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
  'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
  'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
  'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
  'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
  'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
  'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
  'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
  'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
  'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
  'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
  'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
  'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
  'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
];

export const CICIDS2017_LABEL_COLUMN = 'Label';

// UNSW-NB15 feature columns
export const UNSW_NB15_FEATURES = [
  'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload',
  'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin',
  'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
  'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
  'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
  'ct_srv_dst', 'is_sm_ips_ports'
];

export const UNSW_NB15_LABEL_COLUMN = 'label';
export const UNSW_NB15_ATTACK_CAT_COLUMN = 'attack_cat';

// KDD99/NSL-KDD feature columns
export const KDD99_FEATURES = [
  'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
  'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
  'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
  'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
  'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
  'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
  'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
  'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
  'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
];

// Attack category mappings for CICIDS2017
export const CICIDS2017_ATTACK_CATEGORIES: Record<string, string> = {
  'BENIGN': 'Normal',
  'Bot': 'Botnet',
  'DDoS': 'DoS',
  'DoS GoldenEye': 'DoS',
  'DoS Hulk': 'DoS',
  'DoS Slowhttptest': 'DoS',
  'DoS slowloris': 'DoS',
  'FTP-Patator': 'Brute Force',
  'Heartbleed': 'Exploit',
  'Infiltration': 'Infiltration',
  'PortScan': 'Probe',
  'SSH-Patator': 'Brute Force',
  'Web Attack – Brute Force': 'Web Attack',
  'Web Attack – Sql Injection': 'Web Attack',
  'Web Attack – XSS': 'Web Attack'
};

// Attack category mappings for UNSW-NB15
export const UNSW_NB15_ATTACK_CATEGORIES: Record<string, string> = {
  'Normal': 'Normal',
  'Analysis': 'Analysis',
  'Backdoor': 'Backdoor',
  'Backdoors': 'Backdoor',
  'DoS': 'DoS',
  'Exploits': 'Exploit',
  'Fuzzers': 'Fuzzing',
  'Generic': 'Generic',
  'Reconnaissance': 'Probe',
  'Shellcode': 'Shellcode',
  'Worms': 'Worm'
};

// Detect dataset format from CSV headers
export function detectDatasetFormat(headers: string[]): DatasetInfo['format'] {
  const headersLower = headers.map(h => h.toLowerCase().trim());
  
  // Check for CICIDS2017 specific columns
  if (headersLower.includes('flow duration') || headersLower.includes('flow bytes/s')) {
    return 'CICIDS2017';
  }
  
  // Check for UNSW-NB15 specific columns
  if (headersLower.includes('attack_cat') || (headersLower.includes('dur') && headersLower.includes('spkts'))) {
    return 'UNSW-NB15';
  }
  
  // Check for KDD99/NSL-KDD
  if (headersLower.includes('protocol_type') && headersLower.includes('src_bytes')) {
    return 'KDD99';
  }
  
  return 'CUSTOM';
}

// Parse numeric value safely
function parseNumeric(value: string | number | undefined): number {
  if (value === undefined || value === '' || value === null) return 0;
  if (typeof value === 'number') return isNaN(value) ? 0 : value;
  
  const cleaned = value.toString().trim().replace(/[^\d.-]/g, '');
  const parsed = parseFloat(cleaned);
  
  // Handle infinity and NaN
  if (!isFinite(parsed)) return 0;
  return parsed;
}

// Encode categorical variables
const PROTOCOL_ENCODING: Record<string, number> = {
  'tcp': 1, 'udp': 2, 'icmp': 3, '-': 0, '': 0
};

const SERVICE_ENCODING: Record<string, number> = {
  'http': 1, 'https': 2, 'ftp': 3, 'smtp': 4, 'ssh': 5, 'dns': 6,
  'telnet': 7, 'irc': 8, 'pop3': 9, 'snmp': 10, '-': 0, '': 0
};

const FLAG_ENCODING: Record<string, number> = {
  'SF': 1, 'S0': 2, 'REJ': 3, 'RSTR': 4, 'SH': 5, 'RSTO': 6,
  'S1': 7, 'S2': 8, 'S3': 9, 'OTH': 10, 'CON': 11, 'FIN': 12,
  'INT': 13, '-': 0, '': 0
};

export function encodeCategorical(value: string, type: 'protocol' | 'service' | 'flag'): number {
  const lowerValue = (value || '').toLowerCase().trim();
  
  switch (type) {
    case 'protocol':
      return PROTOCOL_ENCODING[lowerValue] ?? 0;
    case 'service':
      return SERVICE_ENCODING[lowerValue] ?? Object.keys(SERVICE_ENCODING).length + 1;
    case 'flag':
      return FLAG_ENCODING[lowerValue] ?? 0;
    default:
      return 0;
  }
}

// Parse CICIDS2017 CSV record
export function parseCICIDS2017Record(row: Record<string, string>, headers: string[]): ParsedRecord {
  const features: Record<string, number> = {};
  const rawData: Record<string, string | number> = {};
  
  // Map header names to normalized names
  const headerMap: Record<string, string> = {};
  headers.forEach(h => {
    headerMap[h.toLowerCase().trim()] = h;
  });
  
  // Extract numerical features
  CICIDS2017_FEATURES.forEach((featureName, idx) => {
    const headerKey = Object.keys(row).find(k => 
      k.toLowerCase().trim() === featureName.toLowerCase()
    );
    
    if (headerKey && row[headerKey] !== undefined) {
      features[`f${idx}`] = parseNumeric(row[headerKey]);
      rawData[featureName] = row[headerKey];
    } else {
      features[`f${idx}`] = 0;
    }
  });
  
  // Get label
  const labelKey = Object.keys(row).find(k => 
    k.toLowerCase().trim() === 'label'
  );
  const rawLabel = labelKey ? (row[labelKey] || 'BENIGN').toString().trim() : 'BENIGN';
  const label = rawLabel === 'BENIGN' ? 'normal' : 'attack';
  const attackCategory = CICIDS2017_ATTACK_CATEGORIES[rawLabel] || rawLabel;
  
  return { features, label, attackCategory, rawData };
}

// Parse UNSW-NB15 CSV record
export function parseUNSWNB15Record(row: Record<string, string>, headers: string[]): ParsedRecord {
  const features: Record<string, number> = {};
  const rawData: Record<string, string | number> = {};
  
  // Extract numerical features
  UNSW_NB15_FEATURES.forEach((featureName, idx) => {
    const headerKey = Object.keys(row).find(k => 
      k.toLowerCase().trim() === featureName.toLowerCase()
    );
    
    if (headerKey && row[headerKey] !== undefined) {
      features[`f${idx}`] = parseNumeric(row[headerKey]);
      rawData[featureName] = row[headerKey];
    } else {
      features[`f${idx}`] = 0;
    }
  });
  
  // Encode categorical features if present
  const protoKey = Object.keys(row).find(k => k.toLowerCase().trim() === 'proto');
  if (protoKey) {
    features['proto_encoded'] = encodeCategorical(row[protoKey], 'protocol');
    rawData['proto'] = row[protoKey];
  }
  
  const serviceKey = Object.keys(row).find(k => k.toLowerCase().trim() === 'service');
  if (serviceKey) {
    features['service_encoded'] = encodeCategorical(row[serviceKey], 'service');
    rawData['service'] = row[serviceKey];
  }
  
  const stateKey = Object.keys(row).find(k => k.toLowerCase().trim() === 'state');
  if (stateKey) {
    features['state_encoded'] = encodeCategorical(row[stateKey], 'flag');
    rawData['state'] = row[stateKey];
  }
  
  // Get label (0 = normal, 1 = attack in UNSW-NB15)
  const labelKey = Object.keys(row).find(k => 
    k.toLowerCase().trim() === 'label'
  );
  const rawLabelValue = labelKey ? parseNumeric(row[labelKey]) : 0;
  const label = rawLabelValue === 0 ? 'normal' : 'attack';
  
  // Get attack category
  const attackCatKey = Object.keys(row).find(k => 
    k.toLowerCase().trim() === 'attack_cat'
  );
  const rawAttackCat = attackCatKey ? row[attackCatKey]?.toString().trim() : '';
  const attackCategory = UNSW_NB15_ATTACK_CATEGORIES[rawAttackCat] || rawAttackCat || 'Normal';
  
  return { features, label, attackCategory, rawData };
}

// Parse KDD99/NSL-KDD record
export function parseKDD99Record(row: Record<string, string>, headers: string[]): ParsedRecord {
  const features: Record<string, number> = {};
  const rawData: Record<string, string | number> = {};
  
  // Process features
  KDD99_FEATURES.forEach((featureName, idx) => {
    const headerKey = Object.keys(row).find(k => 
      k.toLowerCase().trim() === featureName.toLowerCase()
    );
    
    if (headerKey && row[headerKey] !== undefined) {
      // Handle categorical features
      if (featureName === 'protocol_type') {
        features[`f${idx}`] = encodeCategorical(row[headerKey], 'protocol');
      } else if (featureName === 'service') {
        features[`f${idx}`] = encodeCategorical(row[headerKey], 'service');
      } else if (featureName === 'flag') {
        features[`f${idx}`] = encodeCategorical(row[headerKey], 'flag');
      } else {
        features[`f${idx}`] = parseNumeric(row[headerKey]);
      }
      rawData[featureName] = row[headerKey];
    } else {
      features[`f${idx}`] = 0;
    }
  });
  
  // Get label - KDD99 uses attack type names, 'normal.' is normal
  const labelKey = Object.keys(row).find(k => 
    k.toLowerCase().includes('label') || k.toLowerCase().includes('class') || k.toLowerCase().includes('attack')
  ) || headers[headers.length - 1];
  
  const rawLabel = labelKey ? (row[labelKey] || 'normal').toString().trim().toLowerCase() : 'normal';
  const label = rawLabel.includes('normal') ? 'normal' : 'attack';
  
  // Map to attack category
  let attackCategory = 'Normal';
  if (!rawLabel.includes('normal')) {
    if (rawLabel.includes('dos') || rawLabel.includes('neptune') || rawLabel.includes('smurf') || rawLabel.includes('pod') || rawLabel.includes('teardrop') || rawLabel.includes('land') || rawLabel.includes('back')) {
      attackCategory = 'DoS';
    } else if (rawLabel.includes('probe') || rawLabel.includes('satan') || rawLabel.includes('ipsweep') || rawLabel.includes('nmap') || rawLabel.includes('portsweep')) {
      attackCategory = 'Probe';
    } else if (rawLabel.includes('r2l') || rawLabel.includes('ftp_write') || rawLabel.includes('guess_passwd') || rawLabel.includes('imap') || rawLabel.includes('phf') || rawLabel.includes('spy') || rawLabel.includes('warezclient') || rawLabel.includes('warezmaster')) {
      attackCategory = 'R2L';
    } else if (rawLabel.includes('u2r') || rawLabel.includes('buffer_overflow') || rawLabel.includes('loadmodule') || rawLabel.includes('perl') || rawLabel.includes('rootkit')) {
      attackCategory = 'U2R';
    } else {
      attackCategory = 'Unknown';
    }
  }
  
  return { features, label, attackCategory, rawData };
}

// Main CSV parser
export async function parseCSVFile(
  file: File,
  onProgress?: (progress: number) => void
): Promise<{ records: ParsedRecord[]; info: DatasetInfo }> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const lines = text.split(/\r?\n/).filter(line => line.trim());
        
        if (lines.length < 2) {
          reject(new Error('CSV file must have at least a header and one data row'));
          return;
        }
        
        // Parse header
        const headers = parseCSVLine(lines[0]);
        const format = detectDatasetFormat(headers);
        
        const records: ParsedRecord[] = [];
        const labelDistribution: Record<string, number> = {};
        const attackCategories = new Set<string>();
        
        // Parse data rows
        for (let i = 1; i < lines.length; i++) {
          if (onProgress) {
            onProgress(Math.round((i / lines.length) * 100));
          }
          
          try {
            const row = parseCSVLineToObject(lines[i], headers);
            let record: ParsedRecord;
            
            switch (format) {
              case 'CICIDS2017':
                record = parseCICIDS2017Record(row, headers);
                break;
              case 'UNSW-NB15':
                record = parseUNSWNB15Record(row, headers);
                break;
              case 'KDD99':
                record = parseKDD99Record(row, headers);
                break;
              default:
                record = parseGenericRecord(row, headers);
            }
            
            records.push(record);
            labelDistribution[record.label] = (labelDistribution[record.label] || 0) + 1;
            if (record.attackCategory) {
              attackCategories.add(record.attackCategory);
            }
          } catch (err) {
            console.warn(`Skipping malformed row ${i}:`, err);
          }
        }
        
        // Count unique features
        const featureNames = records[0] ? Object.keys(records[0].features) : [];
        
        const info: DatasetInfo = {
          name: file.name,
          format,
          totalRecords: records.length,
          featuresCount: featureNames.length,
          featureNames,
          labelDistribution,
          attackCategories: Array.from(attackCategories)
        };
        
        resolve({ records, info });
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

// Parse generic CSV record for custom formats
function parseGenericRecord(row: Record<string, string>, headers: string[]): ParsedRecord {
  const features: Record<string, number> = {};
  const rawData: Record<string, string | number> = {};
  
  let label = 'normal';
  let attackCategory = 'Normal';
  
  headers.forEach((header, idx) => {
    const value = row[header];
    const headerLower = header.toLowerCase();
    
    // Try to identify label column
    if (headerLower.includes('label') || headerLower.includes('class') || headerLower.includes('attack')) {
      const labelValue = (value || '').toString().toLowerCase().trim();
      if (labelValue === '1' || labelValue === 'attack' || labelValue === 'malicious' || labelValue === 'anomaly') {
        label = 'attack';
        attackCategory = 'Unknown Attack';
      } else if (labelValue === '0' || labelValue === 'normal' || labelValue === 'benign') {
        label = 'normal';
        attackCategory = 'Normal';
      } else {
        label = labelValue.includes('normal') || labelValue.includes('benign') ? 'normal' : 'attack';
        attackCategory = value || 'Unknown';
      }
      rawData[header] = value;
    } else {
      // Treat as numeric feature
      features[`f${idx}`] = parseNumeric(value);
      rawData[header] = value;
    }
  });
  
  return { features, label, attackCategory, rawData };
}

// Parse a single CSV line respecting quotes
function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  
  result.push(current.trim());
  return result;
}

// Parse CSV line to object with headers as keys
function parseCSVLineToObject(line: string, headers: string[]): Record<string, string> {
  const values = parseCSVLine(line);
  const obj: Record<string, string> = {};
  
  headers.forEach((header, idx) => {
    obj[header] = values[idx] || '';
  });
  
  return obj;
}

// Convert parsed records to training data format
export function convertToTrainingData(records: ParsedRecord[]): { features: number[][]; labels: string[] } {
  const features = records.map(r => Object.values(r.features));
  const labels = records.map(r => r.label);
  return { features, labels };
}

// Get feature statistics for visualization
export function getFeatureStatistics(records: ParsedRecord[]): {
  mean: Record<string, number>;
  std: Record<string, number>;
  min: Record<string, number>;
  max: Record<string, number>;
} {
  if (records.length === 0) {
    return { mean: {}, std: {}, min: {}, max: {} };
  }
  
  const featureNames = Object.keys(records[0].features);
  const mean: Record<string, number> = {};
  const std: Record<string, number> = {};
  const min: Record<string, number> = {};
  const max: Record<string, number> = {};
  
  featureNames.forEach(name => {
    const values = records.map(r => r.features[name]).filter(v => isFinite(v));
    const n = values.length;
    
    if (n === 0) {
      mean[name] = 0;
      std[name] = 0;
      min[name] = 0;
      max[name] = 0;
      return;
    }
    
    const sum = values.reduce((a, b) => a + b, 0);
    mean[name] = sum / n;
    
    const sqDiff = values.map(v => Math.pow(v - mean[name], 2));
    std[name] = Math.sqrt(sqDiff.reduce((a, b) => a + b, 0) / n);
    
    min[name] = Math.min(...values);
    max[name] = Math.max(...values);
  });
  
  return { mean, std, min, max };
}
