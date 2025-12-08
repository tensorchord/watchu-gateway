import { useMemo } from "react";
import { Layout, Menu, Typography } from "antd";
import { ApartmentOutlined, BranchesOutlined, DashboardOutlined, LineChartOutlined, RobotOutlined, SafetyCertificateOutlined, ShareAltOutlined } from "@ant-design/icons";
import { Link, Route, Routes, useLocation } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import AgentDashboard from "./pages/AgentDashboard";
import ProcessIndex from "./pages/ProcessIndex";
import ProcessDetails from "./pages/ProcessDetails";
import HeuristicAlerts from "./pages/HeuristicAlerts";
import { SettingsProvider } from "./context/SettingsContext";
import GlobalFilters from "./components/GlobalFilters";
import HighRiskAlertMonitor from "./components/HighRiskAlertMonitor";
import styles from "./components/layout.module.css";

const { Header, Content, Sider } = Layout;

const menuItems = [
    { key: "/timeline", icon: <LineChartOutlined />, label: <Link to="/timeline">Timeline</Link> },
    { key: "/processes", icon: <ApartmentOutlined />, label: <Link to="/processes">Process Explorer</Link> },
    { key: "/security", icon: <SafetyCertificateOutlined />, label: <Link to="/security">Security Analysis</Link> },
    { key: "/alerts", icon: <BranchesOutlined />, label: <Link to="/alerts">Heuristic Alerts</Link> },
    {
        key: "agent-section",
        icon: <RobotOutlined />,
        label: "Agent",
        type: "group",
        children: [
            { key: "/trace", icon: <ShareAltOutlined />, label: <Link to="/trace">Agent Trace Explorer</Link> },
            { key: "/agent-dashboard", icon: <DashboardOutlined />, label: <Link to="/agent-dashboard">Agent Dashboard</Link> }
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
        // Find matching key from flat menu items (including children)
        const flatItems = menuItems.flatMap(item =>
            item.children ? item.children : [item]
        );
        return flatItems.find((item) => location.pathname.startsWith(item.key))?.key ?? location.pathname;
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
                        <Route path="/agent-dashboard" element={<AgentDashboard />} />
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
