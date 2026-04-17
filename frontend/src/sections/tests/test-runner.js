import React, { useState, useEffect } from 'react';
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

const REST_ENDPOINT = process.env.NEXT_PUBLIC_REST_ENDPOINT || '';

const SECTIONS = [
  { id: 1,  label: '§1 Messages & Path Names' },
  { id: 2,  label: '§2 USP Record Handling' },
  { id: 3,  label: '§3 USP Record Test Cases' },
  { id: 4,  label: '§4 General MTP' },
  { id: 5,  label: '§5 CoAP Test Cases (DEPRECATED)', deprecated: true },
  { id: 6,  label: '§6 STOMP' },
  { id: 7,  label: '§7 WebSocket' },
  { id: 8,  label: '§8 Discovery' },
  { id: 9,  label: '§9 Functionality' },
  { id: 10, label: '§10 Bulk Data Collection' },
  { id: 11, label: '§11 MQTT' },
  { id: 12, label: '§12 Software Modules' },
];

const MTP_OPTIONS = ['mqtt', 'ws', 'stomp', 'webpa'];

// Map device API field names to MTP option values.
const DEVICE_MTP_FIELDS = [
  { field: 'Mqtt',       mtp: 'mqtt'  },
  { field: 'Websockets', mtp: 'ws'    },
  { field: 'Stomp',      mtp: 'stomp' },
  { field: 'Webpa',      mtp: 'webpa' },
];

const detectMTPs = (device) =>
  device ? DEVICE_MTP_FIELDS.filter((m) => device[m.field]).map((m) => m.mtp) : [];

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
  const [connectedDevices, setConnectedDevices] = useState([]);
  const [loadingDevices, setLoadingDevices] = useState(false);
  const [mtp, setMtp] = useState('mqtt');
  const [controllerUrl, setControllerUrl] = useState('http://controller:8000');
  const [runName, setRunName] = useState('');
  const [selectedSections, setSelectedSections] = useState([]);
  const [selectedTestIds, setSelectedTestIds] = useState([]);
  const [config, setConfig] = useState(defaultConfig);
  const [configExpanded, setConfigExpanded] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : '';

  useEffect(() => {
    const fetchConnectedDevices = async () => {
      setLoadingDevices(true);
      const url = `${REST_ENDPOINT}/api/device?page_size=50`;
      const token = localStorage.getItem('token');
      console.log('[TestRunner] Fetching devices from:', url);
      console.log('[TestRunner] Token present:', !!token);
      try {
        var myHeaders = new Headers();
        myHeaders.append('Content-Type', 'application/json');
        myHeaders.append('Authorization', token);

        const res = await fetch(url, {
          method: 'GET',
          headers: myHeaders,
          redirect: 'follow',
        });
        console.log('[TestRunner] Device fetch status:', res.status);
        if (res.ok) {
          const data = await res.json();
          console.log('[TestRunner] Device response:', data);
          // Only show online devices (status 2) in the dropdown
          const all = Array.isArray(data.devices) ? data.devices : [];
          const online = all.filter((d) => d.Status === 2);
          console.log('[TestRunner] Total devices:', all.length, '| Online:', online.length);
          setConnectedDevices(online);
        } else if (res.status === 401) {
          console.error('[TestRunner] Unauthorized fetching devices');
        } else if (res.status === 404) {
          console.log('[TestRunner] No devices found (404)');
          setConnectedDevices([]);
        } else {
          const text = await res.text();
          console.error('[TestRunner] Unexpected response:', res.status, text);
        }
      } catch (e) {
        console.error('[TestRunner] Failed to fetch connected devices', e);
      } finally {
        setLoadingDevices(false);
      }
    };
    fetchConnectedDevices();
  }, []);

  const handleDeviceChange = (sn) => {
    setDeviceId(sn);
    const device = connectedDevices.find((d) => d.SN === sn);
    const detected = detectMTPs(device);
    if (detected.length > 0) {
      setMtp(detected[0]);
    }
  };

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
              <FormControl fullWidth size="small" required>
                <InputLabel>Target Device</InputLabel>
                <Select
                  value={deviceId}
                  label="Target Device"
                  onChange={(e) => handleDeviceChange(e.target.value)}
                  disabled={loadingDevices}
                  displayEmpty
                >
                  {loadingDevices ? (
                    <MenuItem disabled>Loading devices…</MenuItem>
                  ) : connectedDevices.length === 0 ? (
                    <MenuItem disabled>No connected devices found</MenuItem>
                  ) : (
                    connectedDevices.map((d) => (
                      <MenuItem key={d.SN} value={d.SN}>
                        {d.Alias ? `${d.SN} — ${d.Alias}` : d.SN}
                      </MenuItem>
                    ))
                  )}
                </Select>
              </FormControl>
              <FormControl fullWidth size="small">
                <InputLabel>MTP</InputLabel>
                <Select value={mtp} label="MTP" onChange={(e) => setMtp(e.target.value)}>
                  {(detectMTPs(connectedDevices.find((d) => d.SN === deviceId)).length > 0
                    ? detectMTPs(connectedDevices.find((d) => d.SN === deviceId))
                    : MTP_OPTIONS
                  ).map((m) => (
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
                      disabled={s.deprecated}
                    />
                  }
                  label={s.label}
                  sx={s.deprecated ? { opacity: 0.38 } : undefined}
                />
              ))}
            </FormGroup>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {selectedSections.length > 0
                ? `Running ${tests.filter((t) => selectedSections.includes(t.section) && !t.disabled).length} tests`
                : `Running all ${tests.filter((t) => !t.disabled).length} tests`}
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardHeader
            title="Individual Tests"
            subheader="Optionally select specific tests to run (overrides section selection). Disabled-by-default tests can be included here."
            action={
              <Button size="small" onClick={() => setSelectedTestIds([])}>
                Clear
              </Button>
            }
          />
          <Divider />
          <CardContent>
            <FormControl fullWidth size="small">
              <InputLabel>Select tests</InputLabel>
              <Select
                multiple
                value={selectedTestIds}
                label="Select tests"
                onChange={(e) => {
                  setSelectedTestIds(e.target.value);
                  setSelectedSections([]);
                }}
                renderValue={(selected) => selected.join(', ')}
              >
                {tests.map((t) => (
                  <MenuItem key={t.id} value={t.id}>
                    <Checkbox checked={selectedTestIds.includes(t.id)} />
                    <Typography variant="body2" sx={{ mr: 1 }}>
                      {t.id} — {t.name}
                    </Typography>
                    {t.disabled && (
                      <Chip label="disabled" size="small" color="error" variant="outlined" sx={{ ml: 'auto' }} />
                    )}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
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
