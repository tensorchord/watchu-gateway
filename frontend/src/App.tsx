import { Layout, Menu, Typography } from "antd";
import { ApartmentOutlined, BranchesOutlined, DashboardOutlined } from "@ant-design/icons";
import { Link, Route, Routes, useLocation } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import ProcessIndex from "./pages/ProcessIndex";
import ProcessDetails from "./pages/ProcessDetails";
import HeuristicAlerts from "./pages/HeuristicAlerts";
import { SettingsProvider } from "./context/SettingsContext";
import GlobalFilters from "./components/GlobalFilters";
import styles from "./components/layout.module.css";

const { Header, Content, Sider } = Layout;

const menuItems = [
    { key: "/", icon: <DashboardOutlined />, label: <Link to="/">Dashboard</Link> },
    { key: "/processes", icon: <ApartmentOutlined />, label: <Link to="/processes">Process Explorer</Link> },
    { key: "/alerts", icon: <BranchesOutlined />, label: <Link to="/alerts">Heuristic Alerts</Link> }
];

function AppShell() {
    const location = useLocation();

    return (
        <Layout>
            <Sider breakpoint="lg" collapsedWidth="0" theme="light">
                <div className={styles.logo}>WatchU</div>
                <Menu mode="inline" selectedKeys={[location.pathname]} items={menuItems} />
            </Sider>
            <Layout>
                <Header className={styles.header}>
                    <Typography.Title level={4} className={styles.title}>
                        Observability & Security Analytics
                    </Typography.Title>
                    <GlobalFilters />
                </Header>
                <Content className={styles.content}>
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/processes" element={<ProcessIndex />} />
                        <Route path="/processes/:rootPid" element={<ProcessDetails />} />
                        <Route path="/alerts" element={<HeuristicAlerts />} />
                        <Route path="*" element={<Dashboard />} />
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
