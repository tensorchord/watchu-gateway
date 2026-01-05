import { Button, Card, Col, Form, Input, message, Row, Select, Space, Table, Tag, Typography, Upload } from "antd";
import type { UploadFile, UploadProps } from "antd";
import type { RcFile } from "antd/es/upload";
import { UploadOutlined } from "@ant-design/icons";
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import dayjs from "dayjs";

import { createSkillSecurityRun, fetchSkillSecurityRun, fetchSkillSecurityRuns, fetchTraceGraph, uploadSkillSecurityArtifact } from "../api/analytics";
import type { SkillSecurityRunCreateRequest, SkillSecurityRunResponse, SkillSecurityUploadResponse, TraceGraphResponse } from "../types/api";
import { useSettings } from "../context/SettingsContext";
import ThreatAnalysis from "../components/ThreatAnalysis";

const { Title, Text } = Typography;

const sourceOptions = [
    { value: "upload", label: "Upload" },
    { value: "github", label: "GitHub" },
    { value: "local", label: "Local Path" }
];

const runnerOptions = [
    { value: "local", label: "Local" },
    { value: "docker", label: "Docker" },
    { value: "k8s", label: "Kubernetes" }
];

const promptOptions = [
    { value: "auto", label: "Auto" },
    { value: "from-skill", label: "From SKILL.md" },
    { value: "examples", label: "Examples" },
    { value: "explicit", label: "Explicit" }
];

function statusTag(status?: string | null) {
    const value = (status ?? "unknown").toLowerCase();
    if (value === "completed") return <Tag color="green">Completed</Tag>;
    if (value === "running") return <Tag color="blue">Running</Tag>;
    if (value === "failed") return <Tag color="red">Failed</Tag>;
    if (value === "pending") return <Tag color="gold">Pending</Tag>;
    return <Tag color="default">Unknown</Tag>;
}

export default function SkillSecurity() {
    const [form] = Form.useForm<SkillSecurityRunCreateRequest>();
    const queryClient = useQueryClient();
    const { host } = useSettings();
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [fileList, setFileList] = useState<UploadFile[]>([]);
    const sourceType = Form.useWatch("source_type", form);

    const runsQuery = useQuery({
        queryKey: ["skill-security-runs"],
        queryFn: () => fetchSkillSecurityRuns({ limit: 50, offset: 0 })
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
            setSelectedId(run.id);
        },
        onError: (err: Error) => {
            message.error(err.message);
        }
    });

    useEffect(() => {
        if (sourceType !== "upload") {
            setFileList([]);
            form.setFieldsValue({ artifact_path: undefined });
        }
    }, [sourceType, form]);

    const uploadProps: UploadProps = {
        fileList,
        maxCount: 1,
        beforeUpload: () => false,
        customRequest: async (options) => {
            try {
                const file = options.file as RcFile;
                const resp: SkillSecurityUploadResponse = await uploadSkillSecurityArtifact(file as File);
                form.setFieldsValue({
                    artifact_path: resp.artifact_path,
                    source_ref: resp.source_ref
                });
                setFileList([{ uid: file.uid, name: resp.source_ref, status: "done" }]);
                options.onSuccess?.(resp, new XMLHttpRequest());
            } catch (err) {
                options.onError?.(err as Error);
                message.error("Upload failed");
            }
        },
        onRemove: () => {
            setFileList([]);
            form.setFieldsValue({ artifact_path: undefined, source_ref: undefined });
            return true;
        }
    };

    const columns = useMemo(() => [
        {
            title: "Created",
            dataIndex: "created_at",
            key: "created_at",
            render: (value: string | null) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "-")
        },
        {
            title: "Source",
            dataIndex: "source_type",
            key: "source_type"
        },
        {
            title: "Runner",
            dataIndex: "runner_mode",
            key: "runner_mode"
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
            render: (value: string | null) => value ?? "-"
        },
        {
            title: "Agent Run",
            dataIndex: "agent_run_id",
            key: "agent_run_id",
            render: (value: string | null) => value ?? "-"
        },
        {
            title: "Action",
            key: "action",
            render: (_: unknown, record: SkillSecurityRunResponse) => (
                <Button type="link" onClick={() => setSelectedId(record.id)}>
                    View
                </Button>
            )
        }
    ], []);

    const selected = selectedQuery.data ?? null;

    const onSubmit = (values: SkillSecurityRunCreateRequest) => {
        createMutation.mutate({
            ...values,
            agent_type: values.agent_type ?? "claude-code",
            prompt_strategy: values.prompt_strategy ?? "auto"
        });
    };

    return (
        <Space direction="vertical" size="large" style={{ width: "100%" }}>
            <Card>
                <Title level={3} style={{ marginBottom: 0 }}>Skill Security Analysis</Title>
                <Text type="secondary">Trigger claude-code with a skill and review threat insights.</Text>
            </Card>

            <Card title="Create Run">
                <Form form={form} layout="vertical" onFinish={onSubmit} initialValues={{ source_type: "github", runner_mode: "local", prompt_strategy: "auto" }}>
                    <Row gutter={16}>
                        <Form.Item name="source_ref" hidden />
                        <Col xs={24} md={6}>
                            <Form.Item label="Source Type" name="source_type" rules={[{ required: true }]}> 
                                <Select options={sourceOptions} />
                            </Form.Item>
                        </Col>
                        <Col xs={24} md={10}>
                            {sourceType === "upload" ? (
                                <Form.Item label="Skill Upload" required>
                                    <Upload {...uploadProps}>
                                        <Button icon={<UploadOutlined />}>Upload Skill</Button>
                                    </Upload>
                                </Form.Item>
                            ) : (
                                <Form.Item label="Source Ref" name="source_ref" rules={[{ required: true }]}>
                                    <Input placeholder="GitHub URL or local path" />
                                </Form.Item>
                            )}
                        </Col>
                        <Col xs={24} md={8}>
                            <Form.Item label="Runner Mode" name="runner_mode" rules={[{ required: true }]}> 
                                <Select options={runnerOptions} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Row gutter={16}>
                        <Col xs={24} md={8}>
                            <Form.Item label="Agent Type" name="agent_type"> 
                                <Input placeholder="claude-code" />
                            </Form.Item>
                        </Col>
                        <Col xs={24} md={8}>
                            <Form.Item label="Prompt Strategy" name="prompt_strategy"> 
                                <Select options={promptOptions} />
                            </Form.Item>
                        </Col>
                        <Col xs={24} md={8}>
                            <Form.Item label="Artifact Path" name="artifact_path">
                                <Input placeholder="Optional resolved path" disabled={sourceType === "upload"} />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Row gutter={16}>
                        <Col xs={24} md={12}>
                            <Form.Item label="Resolved Ref" name="resolved_ref"> 
                                <Input placeholder="Optional commit SHA" />
                            </Form.Item>
                        </Col>
                        <Col xs={24} md={12}>
                            <Form.Item label="Prompt Input (optional)" name="prompt_input"> 
                                <Input.TextArea rows={3} placeholder="Optional prompt to use with the skill" />
                            </Form.Item>
                        </Col>
                    </Row>
                    <Button type="primary" htmlType="submit" loading={createMutation.isPending}>Run</Button>
                </Form>
            </Card>

            <Row gutter={16}>
                <Col xs={24} lg={14}>
                    <Card title="Runs" extra={runsQuery.isFetching ? <Tag color="blue">Refreshing</Tag> : null}>
                        <Table
                            rowKey="id"
                            dataSource={runsQuery.data ?? []}
                            columns={columns}
                            loading={runsQuery.isLoading}
                            pagination={false}
                        />
                    </Card>
                </Col>
                <Col xs={24} lg={10}>
                    <Card title="Run Details">
                        {!selected && <Text type="secondary">Select a run to view details.</Text>}
                        {selected && (
                            <Space direction="vertical" size="middle" style={{ width: "100%" }}>
                                <div>
                                    <Text strong>Status: </Text>{statusTag(selected.status)}
                                </div>
                                <div>
                                    <Text strong>Root Exec ID: </Text><Text>{selected.root_exec_id ?? "-"}</Text>
                                </div>
                                <div>
                                    <Text strong>Agent Run ID: </Text><Text>{selected.agent_run_id ?? "-"}</Text>
                                </div>
                                {selected.error && (
                                    <div>
                                        <Text strong>Error: </Text><Text type="danger">{selected.error}</Text>
                                    </div>
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
                    </Card>
                </Col>
            </Row>
        </Space>
    );
}
