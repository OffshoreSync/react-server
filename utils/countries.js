// Server-side country mapping utility
const OFFSHORE_COUNTRIES = [
  { code: 'US', name: 'United States', rank: 1 },
  { code: 'BR', name: 'Brazil', rank: 2 },
  { code: 'NO', name: 'Norway', rank: 3 },
  { code: 'GB', name: 'United Kingdom', rank: 4 },
  { code: 'MX', name: 'Mexico', rank: 5 },
  { code: 'CN', name: 'China', rank: 6 },
  { code: 'IN', name: 'India', rank: 7 },
  { code: 'CA', name: 'Canada', rank: 8 },
  { code: 'AU', name: 'Australia', rank: 9 },
  { code: 'AZ', name: 'Azerbaijan', rank: 10 },
  { code: 'NG', name: 'Nigeria', rank: 11 },
  { code: 'KW', name: 'Kuwait', rank: 12 },
  { code: 'QA', name: 'Qatar', rank: 13 },
  { code: 'SA', name: 'Saudi Arabia', rank: 14 },
  { code: 'AE', name: 'United Arab Emirates', rank: 15 },
  { code: 'RU', name: 'Russia', rank: 16 },
  { code: 'NL', name: 'Netherlands', rank: 17 },
  { code: 'IT', name: 'Italy', rank: 18 },
  { code: 'DK', name: 'Denmark', rank: 19 },
  { code: 'MY', name: 'Malaysia', rank: 20 }
];

// Helper function to get country code for display
const getCountryCode = (countryName) => {
  if (!countryName) return 'US';

  const country = OFFSHORE_COUNTRIES.find(
    c => c.name.toLowerCase() === countryName.toLowerCase() ||
         countryName.toLowerCase().includes(c.name.toLowerCase())
  );

  return country ? country.code : 'US';
};

module.exports = { 
  OFFSHORE_COUNTRIES, 
  getCountryCode 
};
