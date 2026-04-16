import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  InputAdornment,
  MenuItem,
  OutlinedInput,
  Select,
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
import MagnifyingGlassIcon from '@heroicons/react/24/solid/MagnifyingGlassIcon';
import ArrowPathIcon from '@heroicons/react/24/outline/ArrowPathIcon';
import { SvgIcon } from '@mui/material';

const SECTION_LABELS = {
  1:  'Messages & Path Names',
  2:  'USP Record Handling',
  3:  'USP Record Test Cases',
  4:  'General MTP',
  6:  'STOMP',
  7:  'WebSocket',
  11: 'MQTT',
};

const MTP_COLORS = {
  mqtt: 'primary',
  ws: 'secondary',
  stomp: 'warning',
};

export const TestList = ({ tests, loading, onRefresh }) => {
  const [search, setSearch] = useState('');
  const [sectionFilter, setSectionFilter] = useState('all');

  const sections = [...new Set(tests.map((t) => t.section))].sort((a, b) => a - b);

  const filtered = tests.filter((t) => {
    const matchSearch =
      !search ||
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.id.toLowerCase().includes(search.toLowerCase()) ||
      (t.purpose || '').toLowerCase().includes(search.toLowerCase());
    const matchSection =
      sectionFilter === 'all' || String(t.section) === sectionFilter;
    return matchSearch && matchSection;
  });

  return (
    <Card>
      <CardHeader
        title={`Test Cases (${filtered.length}/${tests.length})`}
        action={
          <Tooltip title="Refresh">
            <IconButton onClick={onRefresh} disabled={loading}>
              <SvgIcon fontSize="small">
                <ArrowPathIcon />
              </SvgIcon>
            </IconButton>
          </Tooltip>
        }
      />
      <Divider />
      <CardContent>
        <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
          <OutlinedInput
            placeholder="Search tests…"
            size="small"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            startAdornment={
              <InputAdornment position="start">
                <SvgIcon fontSize="small">
                  <MagnifyingGlassIcon />
                </SvgIcon>
              </InputAdornment>
            }
            sx={{ flex: 1 }}
          />
          <Select
            size="small"
            value={sectionFilter}
            onChange={(e) => setSectionFilter(e.target.value)}
            sx={{ minWidth: 200 }}
          >
            <MenuItem value="all">All Sections</MenuItem>
            {sections.map((s) => (
              <MenuItem key={s} value={String(s)}>
                §{s} – {SECTION_LABELS[s] || `Section ${s}`}
              </MenuItem>
            ))}
          </Select>
        </Stack>

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={70}>ID</TableCell>
                  <TableCell width={120}>Section</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Purpose</TableCell>
                  <TableCell width={160}>MTPs</TableCell>
                  <TableCell>Tags</TableCell>
                  <TableCell width={90}>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filtered.map((tc) => (
                  <TableRow key={tc.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="bold">
                        {tc.id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        §{tc.section} {SECTION_LABELS[tc.section] || ''}
                      </Typography>
                    </TableCell>
                    <TableCell>{tc.name}</TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {tc.purpose}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {!tc.mtps || tc.mtps.length === 0 ? (
                        <Chip label="All MTPs" size="small" variant="outlined" />
                      ) : (
                        <Stack direction="row" spacing={0.5} flexWrap="wrap">
                          {tc.mtps.map((m) => (
                            <Chip
                              key={m}
                              label={m.toUpperCase()}
                              size="small"
                              color={MTP_COLORS[m] || 'default'}
                            />
                          ))}
                        </Stack>
                      )}
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {(tc.tags || []).map((tag) => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      {tc.disabled && (
                        <Tooltip title="Disabled by default — select individually in Run Tests to include">
                          <Chip label="Disabled" size="small" color="error" variant="outlined" />
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {filtered.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                        No tests match the current filter.
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </CardContent>
    </Card>
  );
};
