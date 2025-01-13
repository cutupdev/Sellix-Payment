const isValidIP = (ip: string) => {
    const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})(\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})){3}$/;
    if (ipv4Pattern.test(ip)) {
        return true;
    }

    // Check for IPv6
    const ipv6Pattern = /^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$/;
    if (ipv6Pattern.test(ip)) {
        return true;
    }

    return false;
};

export default isValidIP;