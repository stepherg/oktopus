import React, { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  LinearProgress,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import ArrowPathIcon from '@heroicons/react/24/outline/ArrowPathIcon';
import TrashIcon from '@heroicons/react/24/outline/TrashIcon';
import ChevronDownIcon from '@heroicons/react/24/outline/ChevronDownIcon';
import ChevronRightIcon from '@heroicons/react/24/outline/ChevronRightIcon';
import { SvgIcon } from '@mui/material';

const STATUS_COLOR = {
  pass: 'success',
  fail: 'error',
  skip: 'default',
  error: 'warning',
  running: 'info',
  completed: 'success',
};

const StatusChip = ({ status }) => (
  <Chip
    label={status?.toUpperCase()}
    color={STATUS_COLOR[status] || 'default'}
    size="small"
  />
);

const RunRow = ({ run, onDelete, taasRequest }) => {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadDetail = async () => {
    if (detail) { setOpen(true); return; }
    setLoadingDetail(true);
    try {
      const d = await taasRequest(`/api/taas/runs/${run.id}`);
      setDetail(d);
      setOpen(true);
    } finally {
      setLoadingDetail(false);
    }
  };

  const passRate = run.summary?.total > 0
    ? Math.round((run.summary.passed / run.summary.total) * 100)
    : 0;

  return (
    <>
      <TableRow hover sx={{ cursor: 'pointer' }}>
        <TableCell onClick={loadDetail}>
          {loadingDetail ? (
            <CircularProgress size={14} />
          ) : (
            <SvgIcon fontSize="small" sx={{ verticalAlign: 'middle' }}>
              {open ? <ChevronDownIcon /> : <ChevronRightIcon />}
            </SvgIcon>
          )}
        </TableCell>
        <TableCell onClick={loadDetail}>
          <Typography variant="body2" fontWeight="bold">{run.name || run.id}</Typography>
          <Typography variant="caption" color="text.secondary">{run.id}</Typography>
        </TableCell>
        <TableCell onClick={loadDetail}>{run.device_id}</TableCell>
        <TableCell onClick={loadDetail}>
          <Chip label={run.mtp?.toUpperCase()} size="small" variant="outlined" />
        </TableCell>
        <TableCell onClick={loadDetail}>
          <StatusChip status={run.status} />
        </TableCell>
        <TableCell onClick={loadDetail}>
          {run.summary ? (
            <Stack>
              <Typography variant="caption">
                {run.summary.passed}/{run.summary.total} passed
                {run.summary.failed > 0 && ` · ${run.summary.failed} failed`}
                {run.summary.errored > 0 && ` · ${run.summary.errored} errors`}
                {run.summary.skipped > 0 && ` · ${run.summary.skipped} skipped`}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={passRate}
                color={passRate === 100 ? 'success' : passRate > 60 ? 'warning' : 'error'}
                sx={{ height: 4, borderRadius: 2 }}
              />
            </Stack>
          ) : '—'}
        </TableCell>
        <TableCell>
          {run.start_time
            ? new Date(run.start_time).toLocaleString()
            : '—'}
        </TableCell>
        <TableCell>
          <Tooltip title="Delete run">
            <IconButton size="small" onClick={() => onDelete(run.id)}>
              <SvgIcon fontSize="small"><TrashIcon /></SvgIcon>
            </IconButton>
          </Tooltip>
        </TableCell>
      </TableRow>

      {/* Detail dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          {detail?.name || 'Run Detail'}
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            {detail?.id}
          </Typography>
        </DialogTitle>
        <DialogContent>
          {detail && (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell width={60}>ID</TableCell>
                    <TableCell>Test Name</TableCell>
                    <TableCell width={80}>Status</TableCell>
                    <TableCell>Steps / Note</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(detail.results || []).map((r) => (
                    <TableRow key={r.test_id} sx={{ bgcolor: r.status === 'fail' ? 'error.lightest' : undefined }}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">{r.test_id}</Typography>
                      </TableCell>
                      <TableCell>{r.test_name}</TableCell>
                      <TableCell><StatusChip status={r.status} /></TableCell>
                      <TableCell>
                        {r.note && (
                          <Typography variant="caption" color="text.secondary" display="block">
                            {r.note}
                          </Typography>
                        )}
                        {(r.steps || []).map((s, i) => (
                          <Stack key={i} direction="row" spacing={1} alignItems="center">
                            <Chip
                              label={s.status?.toUpperCase()}
                              size="small"
                              color={s.status === 'pass' ? 'success' : 'error'}
                            />
                            <Typography variant="caption">{s.description}</Typography>
                            {s.detail && (
                              <Typography variant="caption" color="text.secondary">
                                – {s.detail.length > 100 ? s.detail.slice(0, 100) + '…' : s.detail}
                              </Typography>
                            )}
                          </Stack>
                        ))}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
};

export const TestResults = ({ runs, loading, taasRequest, onRefresh, onDelete }) => {
  return (
    <Card>
      <CardHeader
        title={`Test Runs (${runs.length})`}
        subheader="Click a row to view per-test results"
        action={
          <Tooltip title="Refresh">
            <IconButton onClick={onRefresh} disabled={loading}>
              <SvgIcon fontSize="small"><ArrowPathIcon /></SvgIcon>
            </IconButton>
          </Tooltip>
        }
      />
      <Divider />
      <CardContent sx={{ p: 0 }}>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={30} />
                  <TableCell>Run</TableCell>
                  <TableCell>Device</TableCell>
                  <TableCell>MTP</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Results</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell width={50} />
                </TableRow>
              </TableHead>
              <TableBody>
                {runs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
                      <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                        No test runs yet. Go to "Run Tests" to start one.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  runs.map((run) => (
                    <RunRow
                      key={run.id}
                      run={run}
                      onDelete={onDelete}
                      taasRequest={taasRequest}
                    />
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </CardContent>
    </Card>
  );
};
