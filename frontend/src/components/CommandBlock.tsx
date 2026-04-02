import { CheckOutlined, CopyOutlined } from "@ant-design/icons";
import { Button, Tooltip } from "antd";
import { useState } from "react";
import type React from "react";

interface CommandBlockProps {
    text: string | null;
    size?: "small" | "default";
}

export default function CommandBlock({ text, size = "default" }: CommandBlockProps): React.ReactElement | null {
    const [copied, setCopied] = useState(false);

    if (!text) {
        return null;
    }

    const handleCopy = () => {
        void navigator.clipboard
            .writeText(text)
            .then(() => {
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1500);
            })
            .catch((error) => {
                console.error("Failed to copy command", error);
            });
    };

    const isSmall = size === "small";
    const padding = isSmall ? "10px 12px" : "12px 14px";

    return (
        <div
            style={{
                width: "100%",
                display: "flex",
                alignItems: "stretch",
                borderRadius: 12,
                border: "1px solid rgba(15, 23, 42, 0.12)",
                background: "#0f172a0d",
                overflow: "hidden"
            }}
        >
            <pre
                style={{
                    margin: 0,
                    flex: 1,
                    padding,
                    fontFamily: "Menlo, Consolas, SFMono-Regular, ui-monospace, monospace",
                    fontSize: isSmall ? 12 : 13,
                    lineHeight: 1.55,
                    whiteSpace: "pre-wrap",
                    overflowX: "auto",
                    overflowY: "hidden",
                    wordBreak: "break-word",
                    color: "#0f172a"
                }}
            >
                <code
                    style={{
                        background: "transparent",
                        padding: 0,
                        display: "block",
                        whiteSpace: "inherit"
                    }}
                >
                    {text}
                </code>
            </pre>
            <Tooltip title="Copy command">
                <Button
                    size={isSmall ? "small" : "middle"}
                    icon={copied ? <CheckOutlined /> : <CopyOutlined />}
                    onClick={handleCopy}
                    style={{
                        border: "none",
                        borderLeft: "1px solid rgba(15, 23, 42, 0.12)",
                        borderRadius: 0,
                        padding: isSmall ? "0 12px" : "0 16px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center"
                    }}
                >
                    {copied ? "Copied" : "Copy"}
                </Button>
            </Tooltip>
        </div>
    );
}
