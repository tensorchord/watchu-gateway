import { createContext, ReactNode, useContext, useMemo, useState } from "react";
import dayjs, { Dayjs } from "dayjs";

export type TimeRangePreset = "15m" | "30m" | "1h" | "2h" | "6h" | "24h" | "custom";

export interface SettingsContextValue {
    host: string;
    setHost: (host: string) => void;
    since: Dayjs;
    setSince: (since: Dayjs) => void;
    until: Dayjs;
    setUntil: (until: Dayjs) => void;
    limit: number;
    setLimit: (limit: number) => void;
    rootLimit: number;
    setRootLimit: (limit: number) => void;
    nodeLimit: number;
    setNodeLimit: (limit: number) => void;
    timePreset: TimeRangePreset;
    setTimePreset: (preset: TimeRangePreset) => void;
    autoRefresh: boolean;
    setAutoRefresh: (enabled: boolean) => void;
}

const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);

interface SettingsProviderProps {
    children: ReactNode;
}

const DEFAULT_HOST = "host:ubuntu";
const DEFAULT_LIMIT = 5000;
const DEFAULT_ROOT_LIMIT = 50;
const DEFAULT_NODE_LIMIT = 600;

export function SettingsProvider({ children }: SettingsProviderProps) {
    const [host, setHost] = useState(DEFAULT_HOST);
    const [since, setSince] = useState(dayjs().subtract(1, "hour"));
    const [until, setUntil] = useState(dayjs());
    const [limit, setLimit] = useState(DEFAULT_LIMIT);
    const [rootLimit, setRootLimit] = useState(DEFAULT_ROOT_LIMIT);
    const [nodeLimit, setNodeLimit] = useState(DEFAULT_NODE_LIMIT);
    const [timePreset, setTimePreset] = useState<TimeRangePreset>("1h");
    const [autoRefresh, setAutoRefresh] = useState(true);

    const value = useMemo<SettingsContextValue>(
        () => ({
            host,
            setHost,
            since,
            setSince,
            until,
            setUntil,
            limit,
            setLimit,
            rootLimit,
            setRootLimit,
            nodeLimit,
            setNodeLimit,
            timePreset,
            setTimePreset,
            autoRefresh,
            setAutoRefresh
        }),
        [host, since, until, limit, rootLimit, nodeLimit, timePreset, autoRefresh]
    );

    return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings() {
    const context = useContext(SettingsContext);
    if (!context) {
        throw new Error("useSettings must be used within SettingsProvider");
    }
    return context;
}
