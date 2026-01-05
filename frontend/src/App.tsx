import { useMemo } from "react";
import { Layout, Menu, Typography } from "antd";
import { ApartmentOutlined, BranchesOutlined, DashboardOutlined, DatabaseOutlined, LineChartOutlined, RobotOutlined, SafetyCertificateOutlined, ShareAltOutlined } from "@ant-design/icons";
import { Link, Route, Routes, useLocation } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import DataSources from "./pages/DataSources";
import AgentDashboard from "./pages/AgentDashboard";
import SkillSecurity from "./pages/SkillSecurity";
import ProcessIndex from "./pages/ProcessIndex";
import ProcessDetails from "./pages/ProcessDetails";
import HeuristicAlerts from "./pages/HeuristicAlerts";
import { SettingsProvider } from "./context/SettingsContext";
import GlobalFilters from "./components/GlobalFilters";
import HighRiskAlertMonitor from "./components/HighRiskAlertMonitor";
import styles from "./components/layout.module.css";

const { Header, Content, Sider } = Layout;

type MenuItem = Required<React.ComponentProps<typeof Menu>>["items"];

const menuItems: NonNullable<MenuItem> = [
    { key: "/timeline", icon: <LineChartOutlined />, label: <Link to="/timeline">Timeline</Link> },
    { key: "/processes", icon: <ApartmentOutlined />, label: <Link to="/processes">Process Explorer</Link> },
    { key: "/security", icon: <SafetyCertificateOutlined />, label: <Link to="/security">Security Analysis</Link> },
    { key: "/alerts", icon: <BranchesOutlined />, label: <Link to="/alerts">Heuristic Alerts</Link> },
    { key: "/data-sources", icon: <DatabaseOutlined />, label: <Link to="/data-sources">Data Sources</Link> },
    {
        key: "agent-section",
        label: (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                <RobotOutlined />
                Agent
            </span>
        ),
        type: "group" as const,
        children: [
            { key: "/trace", icon: <ShareAltOutlined />, label: <Link to="/trace">Agent Trace Explorer</Link> },
            { key: "/agent-dashboard", icon: <DashboardOutlined />, label: <Link to="/agent-dashboard">Agent Dashboard</Link> },
            { key: "/skill-security", icon: <SafetyCertificateOutlined />, label: <Link to="/skill-security">Skill Security</Link> }
        ]
    }
];

function AppShell() {
    const location = useLocation();
    const selectedMenuKey = useMemo(() => {
        if (location.pathname === "/") {
            return "/timeline";
        }
        if (location.pathname.startsWith("/processes")) {
            return "/processes";
        }
        const flatKeys: string[] = [
            "/timeline",
            "/processes",
            "/security",
            "/alerts",
            "/data-sources",
            "/trace",
            "/agent-dashboard",
            "/skill-security"
        ];
        return flatKeys.find((key) => location.pathname.startsWith(key)) ?? location.pathname;
    }, [location.pathname]);

    return (
        <Layout>
            <Sider breakpoint="lg" collapsedWidth="0" theme="light">
                <div className={styles.logo}>WatchU</div>
                <Menu mode="inline" selectedKeys={[selectedMenuKey]} items={menuItems} />
            </Sider>
            <Layout>
                <Header className={styles.header}>
                    <Typography.Title level={4} className={styles.title}>
                        Observability & Security Analytics
                    </Typography.Title>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <HighRiskAlertMonitor />
                        <GlobalFilters />
                    </div>
                </Header>
                <Content className={styles.content}>
                    <Routes>
                        <Route path="/" element={<Dashboard view="timeline" />} />
                        <Route path="/timeline" element={<Dashboard view="timeline" />} />
                        <Route path="/trace" element={<Dashboard view="trace" />} />
                        <Route path="/security" element={<Dashboard view="security" />} />
                        <Route path="/data-sources" element={<DataSources />} />
                        <Route path="/agent-dashboard" element={<AgentDashboard />} />
                        <Route path="/skill-security" element={<SkillSecurity />} />
                        <Route path="/processes" element={<ProcessIndex />} />
                        <Route path="/processes/:rootPid" element={<ProcessDetails />} />
                        <Route path="/alerts" element={<HeuristicAlerts />} />
                        <Route path="*" element={<Dashboard view="timeline" />} />
                    </Routes>
                </Content>
            </Layout>
        </Layout>
    );
}

export default function App() {
    return (
        <SettingsProvider>
            <AppShell />
        </SettingsProvider>
    );
}
