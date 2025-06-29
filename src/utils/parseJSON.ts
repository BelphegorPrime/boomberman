export const parseJSON = <T>(jsonString?: string | null): T | undefined => {
    if (!jsonString) {
        return undefined;
    }

    try {
        return JSON.parse(jsonString);
    } catch (error) {
        return undefined;
    }
};
