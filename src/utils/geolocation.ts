
// Simple IP to country mapping utility
// In a real implementation, you'd use a geolocation service or database

interface CountryData {
  code: string;
  name: string;
  lat: number;
  lng: number;
}

const IP_COUNTRY_MAPPING: Record<string, string> = {
  // Common IP ranges to country mappings (simplified)
  "1.": "CN",    // China
  "14.": "CN",   // China
  "27.": "CN",   // China
  "46.": "RU",   // Russia
  "91.": "RU",   // Russia
  "190.": "BR",  // Brazil
  "201.": "BR",  // Brazil
  "103.": "IN",  // India
  "117.": "IN",  // India
  "84.": "DE",   // Germany
  "85.": "DE",   // Germany
  "5.": "IR",    // Iran
  "78.": "TR",   // Turkey
};

const COUNTRY_NAMES: Record<string, string> = {
  "CN": "China",
  "RU": "Russia", 
  "US": "USA",
  "BR": "Brazil",
  "IN": "India",
  "DE": "Germany",
  "IR": "Iran",
  "TR": "Turkey",
  "UK": "United Kingdom",
  "FR": "France",
};

export const getCountryFromIP = (ip: string): string => {
  // Extract first octet for simple mapping
  const firstOctet = ip.split('.')[0];
  const prefix = firstOctet + ".";
  
  // Check known mappings
  for (const [ipPrefix, countryCode] of Object.entries(IP_COUNTRY_MAPPING)) {
    if (prefix.startsWith(ipPrefix)) {
      return COUNTRY_NAMES[countryCode] || countryCode;
    }
  }
  
  // Default mappings based on IP ranges
  const octet = parseInt(firstOctet);
  if (octet >= 1 && octet <= 50) return "China";
  if (octet >= 51 && octet <= 100) return "Russia";
  if (octet >= 101 && octet <= 150) return "USA";
  if (octet >= 151 && octet <= 180) return "Brazil";
  if (octet >= 181 && octet <= 200) return "India";
  if (octet >= 201 && octet <= 220) return "Germany";
  if (octet >= 221 && octet <= 240) return "Iran";
  
  return "Unknown";
};

export const aggregateThreatsByCountry = (threats: Array<{ sourceIP: string; attackType: string }>) => {
  const countryMap = new Map<string, { count: number; types: string[] }>();
  
  threats.forEach(threat => {
    const country = getCountryFromIP(threat.sourceIP);
    const existing = countryMap.get(country) || { count: 0, types: [] };
    
    countryMap.set(country, {
      count: existing.count + 1,
      types: [...existing.types, threat.attackType]
    });
  });
  
  return Array.from(countryMap.entries()).map(([country, data]) => ({
    country,
    count: data.count,
    type: getMostCommonType(data.types)
  })).sort((a, b) => b.count - a.count);
};

const getMostCommonType = (types: string[]): string => {
  const counts = types.reduce((acc, type) => {
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  return Object.entries(counts).reduce((a, b) => 
    counts[a[0]] > counts[b[0]] ? a : b
  )[0] || "Unknown";
};
