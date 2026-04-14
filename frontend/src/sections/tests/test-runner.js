import React, { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  FormControlLabel,
  FormGroup,
  FormLabel,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import BeakerIcon from '@heroicons/react/24/outline/BeakerIcon';
import { SvgIcon } from '@mui/material';

const SECTIONS = [
  { id: 1, label: '§1 Messages & Path Names' },
  { id: 6, label: '§6 STOMP' },
  { id: 7, label: '§7 WebSocket' },
  { id: 11, label: '§11 MQTT' },
];

const MTP_OPTIONS = ['mqtt', 'ws', 'stomp', 'webpa'];

const defaultConfig = {
  multi_instance_object: 'Device.LocalAgent.Subscription.',
  required_param: 'NotifType',
  required_param_value: 'ValueChange',
  writable_param_path: 'Device.LocalAgent.EndpointID',
  readable_param_path: 'Device.DeviceInfo.Manufacturer',
  get_instances_object: 'Device.LocalAgent.Controller.',
  get_supported_dm_object: 'Device.DeviceInfo.',
  invalid_path: 'Device.Bogus.',
  reboot_command: 'Device.Reboot()',
};

export const TestRunner = ({ tests, taasRequest, onRunStarted }) => {
  const [deviceId, setDeviceId] = useState('');
  const [mtp, setMtp] = useState('mqtt');
  const [controllerUrl, setControllerUrl] = useState('http://localhost:8000');
  const [runName, setRunName] = useState('');
  const [selectedSections, setSelectedSections] = useState([]);
  const [selectedTestIds, setSelectedTestIds] = useState([]);
  const [config, setConfig] = useState(defaultConfig);
  const [configExpanded, setConfigExpanded] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : '';

  const handleSectionToggle = (section) => {
    setSelectedSections((prev) =>
      prev.includes(section) ? prev.filter((s) => s !== section) : [...prev, section]
    );
    // Clear individual test selection when toggling sections.
    setSelectedTestIds([]);
  };

  const handleConfigChange = (key, value) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  const handleStartRun = async () => {
    if (!deviceId.trim()) {
      setError('Device ID is required.');
      return;
    }
    if (!controllerUrl.trim()) {
      setError('Controller URL is required.');
      return;
    }
    setError('');
    setSuccess('');
    setRunning(true);

    const body = {
      name: runName || `Run – ${deviceId}`,
      device_id: deviceId.trim(),
      mtp,
      controller_url: controllerUrl.trim(),
      controller_token: token,
      sections: selectedSections,
      test_ids: selectedTestIds,
      config,
    };

    try {
      const res = await taasRequest('/api/taas/runs', 'POST', body);
      if (res.run_id) {
        setSuccess(`Run started: ${res.run_id}`);
        onRunStarted(res.run_id);
      } else {
        setError(res.error || 'Failed to start run.');
      }
    } catch (e) {
      setError('Network error: ' + e.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <Card>
          <CardHeader title="Target Device" />
          <Divider />
          <CardContent>
            <Stack spacing={2}>
              <TextField
                label="Run Name (optional)"
                value={runName}
                onChange={(e) => setRunName(e.target.value)}
                fullWidth
                size="small"
                placeholder="My Test Run"
              />
              <TextField
                label="Device ID (serial number)"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                fullWidth
                size="small"
                required
                placeholder="sn-12345"
              />
              <FormControl fullWidth size="small">
                <InputLabel>MTP</InputLabel>
                <Select value={mtp} label="MTP" onChange={(e) => setMtp(e.target.value)}>
                  {MTP_OPTIONS.map((m) => (
                    <MenuItem key={m} value={m}>
                      {m.toUpperCase()}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField
                label="Controller URL"
                value={controllerUrl}
                onChange={(e) => setControllerUrl(e.target.value)}
                fullWidth
                size="small"
                placeholder="http://localhost:8000"
              />
            </Stack>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card sx={{ height: '100%' }}>
          <CardHeader title="Sections to Run" subheader="Leave all unchecked to run every section" />
          <Divider />
          <CardContent>
            <FormGroup>
              {SECTIONS.map((s) => (
                <FormControlLabel
                  key={s.id}
                  control={
                    <Checkbox
                      checked={selectedSections.includes(s.id)}
                      onChange={() => handleSectionToggle(s.id)}
                    />
                  }
                  label={s.label}
                />
              ))}
            </FormGroup>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {selectedSections.length > 0
                ? `Running ${tests.filter((t) => selectedSections.includes(t.section)).length} tests`
                : `Running all ${tests.length} tests`}
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardHeader
            title="Data Model Configuration"
            subheader="Override default DM paths used by tests"
            action={
              <Button size="small" onClick={() => setConfigExpanded((v) => !v)}>
                {configExpanded ? 'Collapse' : 'Expand'}
              </Button>
            }
          />
          {configExpanded && (
            <>
              <Divider />
              <CardContent>
                <Grid container spacing={2}>
                  {Object.entries(config).map(([key, value]) => (
                    <Grid item xs={12} sm={6} key={key}>
                      <TextField
                        label={key.replace(/_/g, ' ')}
                        value={value}
                        onChange={(e) => handleConfigChange(key, e.target.value)}
                        fullWidth
                        size="small"
                      />
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </>
          )}
        </Card>
      </Grid>

      <Grid item xs={12}>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}
        <Button
          variant="contained"
          size="large"
          onClick={handleStartRun}
          disabled={running}
          startIcon={
            running ? (
              <CircularProgress size={18} color="inherit" />
            ) : (
              <SvgIcon fontSize="small">
                <BeakerIcon />
              </SvgIcon>
            )
          }
        >
          {running ? 'Starting…' : 'Start Test Run'}
        </Button>
      </Grid>
    </Grid>
  );
};
