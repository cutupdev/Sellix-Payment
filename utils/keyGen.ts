import { randomBytes } from "crypto";

const keyGen = async (numKeys: number, keyLength: number = 32) => {
    // Add API key to backend proxy
    try {
        const keys: string[] = [];

        // for (let i = 0; i < numKeys; i++) {

        const key = randomBytes(keyLength / 2).toString('hex');
        // keys.push(key);
        // }

        // console.log("keys ===> ", keys);
        return key;
    } catch (error) {
        console.error("Error generating API key:", error);
        return [];
    }
};

export default keyGen;