import 'dotenv/config';
export const config = {
    VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
    SHODAN_API_KEY: process.env.SHODAN_API_KEY,
    NVD_API_KEY: process.env.NVD_API_KEY,
    ANYRUN_API_KEY: process.env.ANYRUN_API_KEY,
};
