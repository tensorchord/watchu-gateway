declare module "echarts-for-react" {
    import type { CSSProperties, ForwardRefExoticComponent, RefAttributes } from "react";
    import type { ECharts } from "echarts";

    interface ReactEChartsInstance {
        getEchartsInstance?: () => ECharts;
    }

    interface ReactEChartsProps {
        option: unknown;
        notMerge?: boolean;
        lazyUpdate?: boolean;
        style?: CSSProperties;
        className?: string;
        onEvents?: Record<string, (event: unknown) => void>;
    }

    type ReactEChartsComponent = ForwardRefExoticComponent<ReactEChartsProps & RefAttributes<ReactEChartsInstance>>;

    const ReactECharts: ReactEChartsComponent;
    export type { ReactEChartsInstance };
    export default ReactECharts;
}
