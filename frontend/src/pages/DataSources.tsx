import { Card, Col, Row, Typography } from "antd";

import DataSourcesPanel from "../components/DataSourcesPanel";

const { Paragraph, Title } = Typography;

export default function DataSources() {
    return (
        <Row gutter={[24, 24]}>
            <Col span={24}>
                <Card bordered={false} bodyStyle={{ paddingTop: 16 }}>
                    <Title level={4} style={{ marginBottom: 4 }}>
                        Data Sources
                    </Title>
                    <Paragraph type="secondary" style={{ marginBottom: 24 }}>
                        Explore S3 and Postgres access patterns derived from client telemetry.
                    </Paragraph>
                    <DataSourcesPanel />
                </Card>
            </Col>
        </Row>
    );
}

