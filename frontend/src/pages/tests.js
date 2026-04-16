import React, { useState, useEffect } from 'react';
import Head from 'next/head';
import {
  Box,
  Container,
  Typography,
  Tab,
  Tabs,
} from '@mui/material';
import { Layout as DashboardLayout } from 'src/layouts/dashboard/layout';
import { useAuth } from 'src/hooks/use-auth';

import { TestList } from 'src/sections/tests/test-list';
import { TestRunner } from 'src/sections/tests/test-runner';
import { TestResults } from 'src/sections/tests/test-results';

const TAAS_ENDPOINT = process.env.NEXT_PUBLIC_TAAS_ENDPOINT || '';

const Page = () => {
  useAuth();

  const [tab, setTab] = useState(0);
  const [tests, setTests] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loadingTests, setLoadingTests] = useState(false);
  const [loadingRuns, setLoadingRuns] = useState(false);

  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : '';

  const taasRequest = async (path, method = 'GET', body) => {
    const res = await fetch(`${TAAS_ENDPOINT}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: token,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    return res.json();
  };

  const fetchTests = async () => {
    setLoadingTests(true);
    try {
      const data = await taasRequest('/api/taas/tests');
      setTests(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to fetch tests', e);
    } finally {
      setLoadingTests(false);
    }
  };

  const fetchRuns = async () => {
    setLoadingRuns(true);
    try {
      const data = await taasRequest('/api/taas/runs');
      setRuns(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('Failed to fetch runs', e);
    } finally {
      setLoadingRuns(false);
    }
  };

  useEffect(() => {
    fetchTests();
    fetchRuns();
  }, []);

  // Keep polling while any run is still in progress.
  useEffect(() => {
    const hasRunning = runs.some((r) => r.status === 'running');
    if (!hasRunning) return;
    const id = setTimeout(fetchRuns, 5000);
    return () => clearTimeout(id);
  }, [runs]);

  const handleRunStarted = (runId) => {
    setTab(2);
    // Kick off the first refresh; subsequent ones are driven by the effect above.
    setTimeout(fetchRuns, 2000);
  };

  const handleDeleteRun = async (id) => {
    await taasRequest(`/api/taas/runs/${id}`, 'DELETE');
    fetchRuns();
  };

  return (
    <>
      <Head>
        <title>USP Tests (TP-469) | Oktopus</title>
      </Head>
      <Box component="main" sx={{ flexGrow: 1, py: 4 }}>
        <Container maxWidth="xl">
          <Typography variant="h4" sx={{ mb: 3 }}>
            TP-469 USP Conformance Tests
          </Typography>
          <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 3 }}>
            <Tab label="Test Catalogue" />
            <Tab label="Run Tests" />
            <Tab label={`Results (${runs.length})`} />
          </Tabs>

          {tab === 0 && (
            <TestList tests={tests} loading={loadingTests} onRefresh={fetchTests} />
          )}
          {tab === 1 && (
            <TestRunner
              tests={tests}
              taasRequest={taasRequest}
              onRunStarted={handleRunStarted}
            />
          )}
          {tab === 2 && (
            <TestResults
              runs={runs}
              loading={loadingRuns}
              taasRequest={taasRequest}
              onRefresh={fetchRuns}
              onDelete={handleDeleteRun}
            />
          )}
        </Container>
      </Box>
    </>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
