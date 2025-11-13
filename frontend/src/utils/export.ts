import type { ECharts } from "echarts";

type CsvPrimitive = string | number | boolean | null | undefined;

type CsvRow = Record<string, CsvPrimitive>;

function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${filename}.csv`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
}

export function exportRowsToCSV(columns: string[], rows: CsvRow[], filename: string) {
    const headerLine = columns.join(",");
    const dataLines = rows.map((row) =>
        columns
            .map((column) => {
                const value = row[column];
                if (value == null) {
                    return "";
                }
                const text = String(value).replace(/"/g, '""');
                return /,|"|\n/.test(text) ? `"${text}"` : text;
            })
            .join(",")
    );
    const csv = [headerLine, ...dataLines].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    downloadBlob(blob, filename);
}

export async function exportChartAsImage(instance: Pick<ECharts, "getDataURL">, filename: string) {
    const dataUrl = instance.getDataURL({ type: "png", backgroundColor: "#ffffff" });
    const response = await fetch(dataUrl);
    const blob = await response.blob();
    downloadBlob(blob, filename);
}
