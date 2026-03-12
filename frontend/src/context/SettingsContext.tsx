import { createContext, ReactNode, useCallback, useContext, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
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
    const [searchParams, setSearchParams] = useSearchParams();

    const [host, setHostState] = useState(() => searchParams.get("host") ?? DEFAULT_HOST);
    const [since, setSinceState] = useState<Dayjs>(() => {
        const raw = searchParams.get("since");
        return raw ? dayjs(raw) : dayjs().subtract(1, "hour");
    });
    const [until, setUntilState] = useState<Dayjs>(() => {
        const raw = searchParams.get("until");
        return raw ? dayjs(raw) : dayjs();
    });
    const [limit, setLimit] = useState(DEFAULT_LIMIT);
    const [rootLimit, setRootLimit] = useState(DEFAULT_ROOT_LIMIT);
    const [nodeLimit, setNodeLimit] = useState(DEFAULT_NODE_LIMIT);
    const [timePreset, setTimePreset] = useState<TimeRangePreset>(() =>
        searchParams.has("since") ? "custom" : "1h"
    );
    const [autoRefresh, setAutoRefresh] = useState(true);

    const setHost = useCallback(
        (h: string) => {
            setHostState(h);
            setSearchParams((prev) => { prev.set("host", h); return prev; }, { replace: true });
        },
        [setSearchParams]
    );

    const setSince = useCallback(
        (s: Dayjs) => {
            setSinceState(s);
            setSearchParams((prev) => { prev.set("since", s.toISOString()); return prev; }, { replace: true });
        },
        [setSearchParams]
    );

    const setUntil = useCallback(
        (u: Dayjs) => {
            setUntilState(u);
            setSearchParams((prev) => { prev.set("until", u.toISOString()); return prev; }, { replace: true });
        },
        [setSearchParams]
    );

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
        [host, setHost, since, setSince, until, setUntil, limit, rootLimit, nodeLimit, timePreset, autoRefresh]
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
