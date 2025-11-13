import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE_URL;

export const apiClient = axios.create({
    baseURL,
    timeout: 15_000
});

export function toISO8601(value: string | Date): string {
    if (typeof value === "string") {
        return value;
    }
    return value.toISOString();
}
