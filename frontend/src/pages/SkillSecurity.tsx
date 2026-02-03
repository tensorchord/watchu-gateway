import { Button, Card, Col, Collapse, Drawer, Form, Input, message, Modal, Row, Select, Space, Spin, Table, Tag, Tooltip, Typography } from "antd";
import { CheckCircleOutlined, LoadingOutlined, ReloadOutlined, UploadOutlined } from "@ant-design/icons";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import dayjs from "dayjs";
import { Link } from "react-router-dom";

import { createSkillSecurityRun, fetchSkillSecurityRun, fetchSkillSecurityRuns, fetchTraceGraph, uploadSkillSecurityArtifact, fetchSkills, fetchSkillRuns, fetchThreatAnalysis } from "../api/analytics";
import type { SkillSecurityRunCreateRequest, SkillSecurityRunResponse, SkillSecurityUploadResponse, TraceGraphResponse, SkillSummaryResponse, ThreatAnalysisResponse } from "../types/api";
import { useSettings } from "../context/SettingsContext";
import ThreatAnalysis from "../components/ThreatAnalysis";
import RunnerOutputViewer from "../components/RunnerOutputViewer";

const { Title, Text } = Typography;

function getThreatLevelColor(level: number): string {
    if (level >= 5) return "#f5222d";
    if (level >= 4) return "#fa8c16";
    if (level >= 3) return "#faad14";
    return "#52c41a";
}

function getThreatLevelLabel(level: number): string {
    if (level >= 5) return "Critical";
    if (level >= 4) return "High";
    if (level >= 3) return "Medium";
    return "Low";
}

const sourceOptions = [
    { value: "registry", label: "Skill Registry" },
    { value: "upload", label: "Upload" },
    { value: "github", label: "GitHub" }
];

const runnerOptions = [
    { value: "local", label: "Local" },
    { value: "docker", label: "Docker" },
    { value: "k8s", label: "Kubernetes" }
];

const agentOptions = [
    { value: "claude-code", label: "claude-code" }
];

const promptOptions = [
    { value: "from-skill", label: "From SKILL.md" },
    { value: "custom", label: "Custom prompt" }
];

function statusTag(status?: string | null) {
    const value = (status ?? "unknown").toLowerCase();
    if (value === "completed") return <Tag icon={<CheckCircleOutlined />} color="green">Completed</Tag>;
    if (value === "running") return <Tag icon={<LoadingOutlined spin />} color="blue">Running</Tag>;
    if (value === "failed") return <Tag color="red">Failed</Tag>;
    if (value === "pending") return <Tag color="gold">Pending</Tag>;
    return <Tag color="default">Unknown</Tag>;
}

function compactId(value: string, head = 6, tail = 6) {
    if (!value) return value;
    if (value.length <= head + tail + 3) return value;
    return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export default function SkillSecurity() {
    const [form] = Form.useForm<SkillSecurityRunCreateRequest>();
    const [modalForm] = Form.useForm<SkillSecurityRunCreateRequest>();
    const queryClient = useQueryClient();
    const { host } = useSettings();
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [uploadedName, setUploadedName] = useState<string | null>(null);
    const [uploading, setUploading] = useState(false);
    const [expandedSkillKeys, setExpandedSkillKeys] = useState<React.Key[]>([]);
    const [runModalOpen, setRunModalOpen] = useState(false);
    const [selectedSkill, setSelectedSkill] = useState<SkillSummaryResponse | null>(null);
    const fileInputRef = useRef<HTMLInputElement | null>(null);
    const sourceType = Form.useWatch("source_type", form);
    const promptStrategy = Form.useWatch("prompt_strategy", form);
    const [threatCache, setThreatCache] = useState<Record<string, ThreatAnalysisResponse>>({});
    const [loadingThreats, setLoadingThreats] = useState<Set<string>>(new Set());
    const skillsTableRef = useRef<HTMLDivElement | null>(null);

    const handleSkillClick = (skillName: string, sourceType: string) => {
        // Close the analysis drawer
        setSelectedId(null);

        // Find the skill in the list and expand it
        const skill = skillsQuery.data?.find(
            s => s.source_ref === skillName && s.source_type === sourceType
        );

        if (skill) {
            const key = `${skill.source_ref}-${skill.artifact_path || ""}`;
            setExpandedSkillKeys([key]);

            // Scroll to the skills table
            setTimeout(() => {
                skillsTableRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
            }, 100);
        }
    };
    const runsQuery = useQuery({
        queryKey: ["skill-security-runs"],
        queryFn: () => fetchSkillSecurityRuns({ limit: 50, offset: 0 })
    });

    const skillsQuery = useQuery({
        queryKey: ["skills"],
        queryFn: () => fetchSkills({ limit: 50 })
    });

    const selectedQuery = useQuery({
        queryKey: ["skill-security-run", selectedId],
        queryFn: () => fetchSkillSecurityRun(selectedId ?? ""),
        enabled: Boolean(selectedId)
    });

    const traceQuery = useQuery<TraceGraphResponse>({
        queryKey: ["skill-security-trace", host, selectedQuery.data?.agent_run_id],
        queryFn: () => fetchTraceGraph(host ?? "", selectedQuery.data?.agent_run_id ?? ""),
        enabled: Boolean(host) && Boolean(selectedQuery.data?.agent_run_id)
    });

    const createMutation = useMutation({
        mutationFn: (payload: SkillSecurityRunCreateRequest) => createSkillSecurityRun(payload),
        onSuccess: (run) => {
            message.success("Skill run created");
            queryClient.invalidateQueries({ queryKey: ["skill-security-runs"] });
            queryClient.invalidateQueries({ queryKey: ["skills"] });
            setSelectedId(run.id);
        },
        onError: (err: Error) => {
            message.error(err.message);
        }
    });

    useEffect(() => {
        if (!sourceType) {
            form.setFieldsValue({ source_type: "upload" });
        }
        if (sourceType !== "upload") {
            setUploadedName(null);
            form.setFieldsValue({ artifact_path: undefined, source_ref: undefined });
        }
    }, [sourceType, form]);

    useEffect(() => {
        if (promptStrategy !== "custom") {
            form.setFieldsValue({ prompt_input: undefined });
        }
    }, [promptStrategy, form]);

    // Load threat analysis for completed runs
    useEffect(() => {
        const runs = runsQuery.data ?? [];
        const completedRuns = runs.filter((r) => r.status === "completed" && r.root_exec_id);
        console.log("ThreatAnalysis: runs:", runs.length, "completed:", completedRuns.length, "cache:", Object.keys(threatCache));

        completedRuns.forEach((run) => {
            const rootExecId = run.root_exec_id;
            if (!rootExecId || threatCache[rootExecId]) return;

            console.log("Fetching threat analysis for:", rootExecId);
            setLoadingThreats((prev) => new Set([...prev, rootExecId]));

            fetchThreatAnalysis(rootExecId)
                .then((result) => {
                    console.log("Got threat analysis result:", result);
                    if (result && result.threat_level) {
                        setThreatCache((prev) => ({ ...prev, [rootExecId]: result }));
                    }
                })
                .catch((err) => {
                    console.error("Failed to fetch threat analysis:", err);
                })
                .finally(() => {
                    setLoadingThreats((prev) => {
                        const next = new Set(prev);
                        next.delete(rootExecId);
                        return next;
                    });
                });
        });
    }, [runsQuery.data]);

    const clearUpload = () => {
        setUploadedName(null);
        form.setFieldsValue({ artifact_path: undefined, source_ref: undefined });
    };

    useEffect(() => {
        if (sourceType === "upload" && fileInputRef.current) {
            fileInputRef.current.setAttribute("webkitdirectory", "true");
            fileInputRef.current.setAttribute("directory", "true");
        }
    }, [sourceType]);

    const handleFileSelect = async (event: ChangeEvent<HTMLInputElement>) => {
        const files = Array.from(event.target.files ?? []);
        if (files.length === 0) return;

        // Check if SKILL.md exists in uploaded files
        const hasSkillMd = files.some((file) => {
            const name = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
            return name.endsWith("SKILL.md") || name.endsWith("/SKILL.md");
        });

        if (!hasSkillMd) {
            message.error("SKILL.md file is required in the uploaded skill directory. Please ensure your skill contains a SKILL.md file.");
            event.target.value = "";
            return;
        }

        setUploading(true);
        try {
            const resp: SkillSecurityUploadResponse = await uploadSkillSecurityArtifact(files);
            const firstRel = (files[0] as File & { webkitRelativePath?: string }).webkitRelativePath;
            const displayName = firstRel && firstRel.includes("/") ? firstRel.split("/")[0] : resp.source_ref;
            form.setFieldsValue({
                artifact_path: resp.artifact_path,
                source_ref: resp.source_ref
            });
            setUploadedName(displayName);
            message.success("Upload complete");
        } catch (err) {
            message.error("Upload failed");
            clearUpload();
        } finally {
            setUploading(false);
            event.target.value = "";
        }
    };

    const columns = useMemo(() => [
        {
            title: "Skill",
            key: "skill",
            render: (_: unknown, record: SkillSecurityRunResponse) => {
                const skillName = record.skill_name;
                const sourceType = record.skill_source_type;
                if (!skillName) return <Text type="secondary">-</Text>;

                return (
                    <Space size="small" style={{ alignItems: "center" }}>
                        <Text
                            strong
                            style={{
                                color: "#000000",
                                fontSize: 13
                            }}
                        >
                            {skillName}
                        </Text>
                        {sourceType && (
                            <>
                                <Text type="secondary" style={{ fontSize: 12 }}>•</Text>
                                <Text type="secondary" style={{ fontSize: 12 }}>{sourceType}</Text>
                            </>
                        )}
                    </Space>
                );
            }
        },
        {
            title: "Created",
            dataIndex: "created_at",
            key: "created_at",
            render: (value: string | null) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "-")
        },
        {
            title: "Runner",
            dataIndex: "runner_mode",
            key: "runner_mode"
        },
        {
            title: "Prompt",
            key: "prompt",
            ellipsis: true,
            render: (_: unknown, record: SkillSecurityRunResponse) => {
                const prompt = record.prompt_input;
                if (!prompt) return <Text type="secondary">-</Text>;
                const preview = prompt.length > 50 ? prompt.slice(0, 50) + "..." : prompt;
                return (
                    <Tooltip title={prompt}>
                        <Text style={{ fontSize: 12 }}>{preview}</Text>
                    </Tooltip>
                );
            }
        },
        {
            title: "Status",
            dataIndex: "status",
            key: "status",
            render: (value: string) => statusTag(value)
        },
        {
            title: "Root Exec",
            dataIndex: "root_exec_id",
            key: "root_exec_id",
            ellipsis: true,
            render: (value: string | null) => {
                if (!value) return "-";
                return (
                    <Tooltip title={value}>
                        <Link to={`/processes?root_exec_id=${encodeURIComponent(value)}`}>
                            {compactId(value)}
                        </Link>
                    </Tooltip>
                );
            }
        },
        {
            title: "Agent Run",
            dataIndex: "agent_run_id",
            key: "agent_run_id",
            ellipsis: true,
            render: (value: string | null) => {
                if (!value) return "-";
                return (
                    <Tooltip title={value}>
                        <Text>{compactId(value)}</Text>
                    </Tooltip>
                );
            }
        },
        {
            title: "Threat Level",
            key: "threat_level",
            render: (_: unknown, record: SkillSecurityRunResponse) => {
                // Don't show loading for threat analysis, just show the result or -
                const rootExecId = record.root_exec_id;
                if (!rootExecId) return <Text type="secondary">-</Text>;

                const threat = threatCache[rootExecId];
                if (!threat) return <Text type="secondary">-</Text>;

                const level = threat.threat_level;
                const label = getThreatLevelLabel(level);
                const color = getThreatLevelColor(level);

                return <Tag color={color} style={{ margin: 0 }}>{label}</Tag>;
            }
        },
        {
            title: "Threat Type",
            key: "threat_type",
            ellipsis: true,
            render: (_: unknown, record: SkillSecurityRunResponse) => {
                // Don't show loading for threat analysis, just show the result or -
                const rootExecId = record.root_exec_id;
                if (!rootExecId) return <Text type="secondary">-</Text>;

                const threat = threatCache[rootExecId];
                if (!threat) return <Text type="secondary">-</Text>;

                return (
                    <Tooltip title={threat.threat_type}>
                        <Text style={{ fontSize: 12 }}>{threat.threat_type}</Text>
                    </Tooltip>
                );
            }
        },
        {
            title: "Details",
            key: "action",
            render: (_: unknown, record: SkillSecurityRunResponse) => (
                <Button type="link" onClick={() => setSelectedId(record.id)}>
                    View
                </Button>
            )
        }
    ], [threatCache, loadingThreats]);

    const selected = selectedQuery.data ?? null;
    const sourceRefLabel = sourceType === "registry" ? "Registry Ref" : "Source Ref";
    const sourceRefPlaceholder = sourceType === "registry" ? "owner/repo/skill" : "https://github.com/owner/repo";
    const validateRegistryRef = (_: unknown, value?: string) => {
        if (sourceType !== "registry") return Promise.resolve();
        const trimmed = (value ?? "").trim();
        if (!trimmed) return Promise.reject(new Error("Registry ref is required"));
        const segments = trimmed.split("/").filter(Boolean);
        if (segments.length !== 3) {
            return Promise.reject(new Error("Use owner/repo/skill format"));
        }
        return Promise.resolve();
    };

    const onSubmit = (values: SkillSecurityRunCreateRequest) => {
        createMutation.mutate({
            ...values,
            agent_type: values.agent_type ?? "claude-code",
            prompt_strategy: values.prompt_strategy ?? "from-skill"
        });
    };

    const handleRunSkillClick = (skill: SkillSummaryResponse) => {
        const formValues = form.getFieldsValue();
        setSelectedSkill(skill);
        modalForm.setFieldsValue({
            runner_mode: formValues.runner_mode || "local",
            agent_type: formValues.agent_type || "claude-code",
            prompt_strategy: formValues.prompt_strategy || "from-skill",
            prompt_input: formValues.prompt_input
        });
        setRunModalOpen(true);
    };

    const handleRunModalOk = () => {
        const values = modalForm.getFieldsValue();
        if (!selectedSkill) return;

        createMutation.mutate({
            source_type: selectedSkill.source_type,
            source_ref: selectedSkill.source_ref,
            artifact_path: selectedSkill.artifact_path,
            runner_mode: values.runner_mode || "local",
            agent_type: values.agent_type || "claude-code",
            prompt_strategy: values.prompt_strategy || "from-skill",
            prompt_input: values.prompt_input
        });
        setRunModalOpen(false);
    };

    return (
        <Space direction="vertical" size="large" style={{ width: "100%" }}>
            <Card>
                <Title level={3} style={{ marginBottom: 0 }}>Skill Security Analysis</Title>
                <Text type="secondary">Trigger claude-code with a skill and review threat insights.</Text>
            </Card>

            <Card title="Create Run">
                <Form
                    form={form}
                    layout="vertical"
                    onFinish={onSubmit}
                    initialValues={{ source_type: "upload", runner_mode: "local", prompt_strategy: "from-skill", agent_type: "claude-code" }}
                >
                    <Row gutter={16}>
                        <Form.Item name="source_ref" hidden />
                        <Form.Item name="artifact_path" hidden />
                        <Col xs={24} md={6}>
                            <Form.Item label="Source Type" name="source_type" rules={[{ required: true }]}>
                                <Select options={sourceOptions} />
                            </Form.Item>
                        </Col>
                        <Col xs={24} md={10}>
                            {sourceType === "upload" ? (
                                <Form.Item label="Skill Upload" required>
                                    <input
                                        ref={fileInputRef}
                                        id="skill-upload-input"
                                        type="file"
                                        multiple
                                        style={{ position: "absolute", opacity: 0, width: 0, height: 0 }}
                                        onChange={handleFileSelect}
                                    />
                                    <Space size="small" wrap>
                                        <label htmlFor="skill-upload-input">
                                            <Button
                                                icon={<UploadOutlined />}
                                                loading={uploading}
                                                htmlType="button"
                                                onClick={() => fileInputRef.current?.click()}
                                            >
                                                Upload Folder
                                            </Button>
                                        </label>
                                        {uploadedName && <Tag color="blue">{uploadedName}</Tag>}
                                        {uploadedName && (
                                            <Button size="small" type="link" onClick={clearUpload}>
                                                Remove
                                            </Button>
                                        )}
                                    </Space>
                                </Form.Item>
                            ) : (
                                <Form.Item
                                    label={sourceRefLabel}
                                    name="source_ref"
                                    rules={[
                                        { required: true, message: "Source ref is required" },
                                        { validator: validateRegistryRef }
                                    ]}
                                >
                                    <Input placeholder={sourceRefPlaceholder} />
                                </Form.Item>
                            )}
                        </Col>
                        <Col xs={24} md={8}>
                            <Form.Item label="Runner Mode" name="runner_mode" rules={[{ required: true }]}>
                                <Select options={runnerOptions} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Collapse>
                        <Collapse.Panel header="Optional settings" key="optional">
                            <Row gutter={16}>
                                <Col xs={24} md={8}>
                                    <Form.Item label="Agent Type" name="agent_type">
                                        <Select options={agentOptions} placeholder="Select agent type" allowClear />
                                    </Form.Item>
                                </Col>
                                <Col xs={24} md={8}>
                                    <Form.Item label="Prompt Strategy" name="prompt_strategy">
                                        <Select options={promptOptions} />
                                    </Form.Item>
                                </Col>
                            </Row>
                            <Row gutter={16}>
                                {promptStrategy === "custom" && (
                                    <Col xs={24}>
                                        <Form.Item
                                            label="Prompt Input"
                                            name="prompt_input"
                                            rules={[{ required: true, message: "Please provide the custom prompt." }]}
                                        >
                                            <Input.TextArea rows={3} placeholder="Enter the prompt to use with the skill" />
                                        </Form.Item>
                                    </Col>
                                )}
                            </Row>
                        </Collapse.Panel>
                    </Collapse>
                    <Button type="primary" htmlType="submit" loading={createMutation.isPending}>Run</Button>
                </Form>
            </Card>

            <div ref={skillsTableRef}>
                <Card
                    title="Skills"
                    extra={
                        <Space>
                            {skillsQuery.isFetching && <Tag color="blue">Refreshing</Tag>}
                            <Button
                                icon={<ReloadOutlined />}
                                size="small"
                                onClick={() => skillsQuery.refetch()}
                                loading={skillsQuery.isFetching}
                            >
                                Refresh
                            </Button>
                        </Space>
                    }
                >
                    <Table
                        rowKey={(record: SkillSummaryResponse) => `${record.source_ref}-${record.artifact_path || ""}`}
                        dataSource={skillsQuery.data ?? []}
                        loading={skillsQuery.isLoading}
                        pagination={false}
                        expandable={{
                            expandedRowRender: (skill: SkillSummaryResponse) => {
                                const skillRuns = (runsQuery.data ?? []).filter(
                                    run => run.source_ref === skill.source_ref &&
                                        (!skill.artifact_path || run.artifact_path === skill.artifact_path)
                                );
                                return (
                                    <Table
                                        rowKey="id"
                                        dataSource={skillRuns}
                                        pagination={false}
                                        columns={columns}
                                        size="small"
                                        title={() => (
                                            <Space style={{ width: "100%", justifyContent: "space-between" }}>
                                                <Text strong>Runs ({skillRuns.length})</Text>
                                                <Button
                                                    icon={<ReloadOutlined />}
                                                    size="small"
                                                    onClick={() => runsQuery.refetch()}
                                                    loading={runsQuery.isFetching}
                                                >
                                                    Refresh
                                                </Button>
                                            </Space>
                                        )}
                                    />
                                );
                            },
                            expandIcon: ({ expanded, onExpand, record }) => {
                                if (expanded) {
                                    return <Button type="link" onClick={(e) => onExpand(record, e)}>Collapse</Button>;
                                }
                                return <Button type="link" onClick={(e) => onExpand(record, e)}>View Runs ({record.run_count})</Button>;
                            },
                            onExpand: (expanded, record) => {
                                const key = `${record.source_ref}-${record.artifact_path || ""}`;
                                if (expanded) {
                                    setExpandedSkillKeys([...expandedSkillKeys, key]);
                                } else {
                                    setExpandedSkillKeys(expandedSkillKeys.filter((k) => k !== key));
                                }
                            },
                            expandedRowKeys: expandedSkillKeys,
                            expandIconColumnIndex: 0
                        }}
                        columns={[
                            {
                                title: "Skill Name",
                                dataIndex: "source_ref",
                                key: "source_ref",
                                width: 200,
                                ellipsis: true
                            },
                            {
                                title: "Type",
                                dataIndex: "source_type",
                                key: "source_type",
                                width: 80
                            },
                            {
                                title: "Runs",
                                dataIndex: "run_count",
                                key: "run_count",
                                width: 60,
                                render: (value: number) => <Tag>{value}</Tag>
                            },
                            {
                                title: "Last Run",
                                dataIndex: "last_run_at",
                                key: "last_run_at",
                                width: 160,
                                render: (value: string | null) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "-")
                            },
                            {
                                title: "Action",
                                key: "action",
                                width: 70,
                                align: "center",
                                render: (_: unknown, record: SkillSummaryResponse) => (
                                    <Button
                                        type="primary"
                                        size="small"
                                        onClick={() => handleRunSkillClick(record)}
                                    >
                                        Run
                                    </Button>
                                )
                            }
                        ]}
                    />
                </Card>
            </div>

            <Drawer
                title="Run Details"
                placement="right"
                width={720}
                open={Boolean(selectedId)}
                onClose={() => setSelectedId(null)}
                destroyOnClose
            >
                {selectedQuery.isLoading && <Spin size="large" />}
                {selected && (
                    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
                        <div>
                            <Text strong>Status: </Text>{statusTag(selected.status)}
                        </div>
                        {selected.skill_name && (
                            <div>
                                <Text strong>Skill: </Text>
                                <Button
                                    type="link"
                                    style={{ padding: 0, height: "auto", color: "#3b82f6", textDecoration: "underline" }}
                                    onClick={() => handleSkillClick(selected.skill_name!, selected.skill_source_type || "")}
                                >
                                    {selected.skill_name}
                                </Button>
                            </div>
                        )}
                        <div>
                            <Text strong>Prompt Strategy: </Text><Text>{selected.prompt_strategy}</Text>
                        </div>
                        {selected.prompt_input && (
                            <div>
                                <Text strong>Prompt: </Text>
                                <pre style={{ whiteSpace: "pre-wrap", marginTop: 8, padding: 12, background: "#f5f5f5", borderRadius: 4 }}>{selected.prompt_input}</pre>
                            </div>
                        )}
                        <div>
                            <Text strong>Root Exec ID: </Text><Text>{selected.root_exec_id ?? "-"}</Text>
                        </div>
                        <div>
                            <Text strong>Agent Run ID: </Text><Text>{selected.agent_run_id ?? "-"}</Text>
                        </div>
                        {selected.runner_exit_code != null && (
                            <div>
                                <Text strong>Exit Code: </Text><Text>{selected.runner_exit_code}</Text>
                            </div>
                        )}
                        {selected.error && (
                            <div>
                                <Text strong>Error: </Text><Text type="danger">{selected.error}</Text>
                            </div>
                        )}
                        {selected.runner_output && (
                            <Collapse defaultActiveKey={[]} size="small">
                                <Collapse.Panel header="Runner Output" key="runner-output">
                                    <RunnerOutputViewer output={selected.runner_output} />
                                </Collapse.Panel>
                            </Collapse>
                        )}
                        {selected.root_exec_id && <ThreatAnalysis rootExecId={selected.root_exec_id} />}
                        {selected.agent_run_id && host && (
                            <Card size="small" title="Trace Graph Summary">
                                {traceQuery.isLoading && <Text type="secondary">Loading trace graph...</Text>}
                                {traceQuery.data && (
                                    <Text type="secondary">{traceQuery.data.traces.length} trace nodes captured.</Text>
                                )}
                                {!host && <Text type="secondary">Select a host in filters to load traces.</Text>}
                            </Card>
                        )}
                    </Space>
                )}
            </Drawer>

            <Modal
                title={`Run ${selectedSkill?.source_ref || "Skill"}`}
                open={runModalOpen}
                onOk={handleRunModalOk}
                onCancel={() => setRunModalOpen(false)}
                confirmLoading={createMutation.isPending}
                width={600}
            >
                <Form
                    form={modalForm}
                    layout="vertical"
                    initialValues={{ runner_mode: "local", agent_type: "claude-code", prompt_strategy: "from-skill" }}
                >
                    <Form.Item label="Runner Mode" name="runner_mode" rules={[{ required: true }]}>
                        <Select options={runnerOptions} />
                    </Form.Item>
                    <Form.Item label="Agent Type" name="agent_type">
                        <Select options={agentOptions} />
                    </Form.Item>
                    <Form.Item label="Prompt Strategy" name="prompt_strategy" rules={[{ required: true }]}>
                        <Select options={promptOptions} />
                    </Form.Item>
                    <Form.Item shouldUpdate={(prevValues, currentValues) => currentValues.prompt_strategy === 'custom'}>
                        {({ getFieldValue }) =>
                            getFieldValue('prompt_strategy') === 'custom' ? (
                                <Form.Item
                                    label="Prompt Input"
                                    name="prompt_input"
                                    rules={[{ required: true, message: 'Please provide the custom prompt.' }]}
                                >
                                    <Input.TextArea rows={3} placeholder="Enter the prompt to use with the skill" />
                                </Form.Item>
                            ) : null
                        }
                    </Form.Item>
                </Form>
            </Modal>
        </Space>
    );
}
