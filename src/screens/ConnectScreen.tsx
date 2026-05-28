import React, { useState } from 'react';
import {
  View, Text, TextInput, Switch, TouchableOpacity,
  StyleSheet, ScrollView, ActivityIndicator,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { colors } from '../theme';
import { VpnStatus } from '../hooks/useVpn';

const STORAGE_KEY = 'dvion_connect_form';

interface Props {
  status: VpnStatus;
  onConnect:    (server: string, authKey: string, fullTunnel: boolean, fp?: string) => Promise<void>;
  onDisconnect: () => Promise<void>;
}

export default function ConnectScreen({ status, onConnect, onDisconnect }: Props) {
  const [server,      setServer]      = useState('');
  const [authKey,     setAuthKey]     = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [fullTunnel,  setFullTunnel]  = useState(false);
  const [busy,        setBusy]        = useState(false);
  const [error,       setError]       = useState('');

  React.useEffect(() => {
    AsyncStorage.getItem(STORAGE_KEY).then(raw => {
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.server)      setServer(saved.server);
      if (saved.authKey)     setAuthKey(saved.authKey);
      if (saved.fingerprint) setFingerprint(saved.fingerprint);
      if (saved.fullTunnel != null) setFullTunnel(saved.fullTunnel);
    }).catch(() => {});
  }, []);

  const save = () =>
    AsyncStorage.setItem(STORAGE_KEY, JSON.stringify({ server, authKey, fingerprint, fullTunnel }));

  const handleConnect = async () => {
    setError('');
    if (!server.trim())  { setError('Server address is required'); return; }
    if (!authKey.trim()) { setError('Auth key is required'); return; }
    setBusy(true);
    try {
      await save();
      await onConnect(server.trim(), authKey.trim(), fullTunnel, fingerprint.trim() || undefined);
    } catch (e: any) {
      setError(e?.message ?? 'Connection failed');
    } finally {
      setBusy(false);
    }
  };

  const handleDisconnect = async () => {
    setBusy(true);
    try { await onDisconnect(); } catch { /* ignore */ } finally { setBusy(false); }
  };

  if (status.running) {
    return (
      <View style={styles.page}>
        <View style={styles.card}>
          <View style={styles.runningRow}>
            <View style={styles.runningDot} />
            <Text style={styles.runningText}>Connected · {status.mode} mode</Text>
          </View>
          <TouchableOpacity style={[styles.btn, styles.btnDanger]} onPress={handleDisconnect} disabled={busy}>
            {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Disconnect</Text>}
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Server</Text>
        <Field label="SERVER ADDRESS" value={server} onChange={setServer} placeholder="vpn.example.com:51820" />
        <Field label="AUTH KEY"       value={authKey} onChange={setAuthKey} placeholder="dvion-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" secure />
        <Field label="SERVER TLS FINGERPRINT (optional)" value={fingerprint} onChange={setFingerprint} placeholder="AA:BB:CC:…" mono />
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Options</Text>
        <View style={styles.toggleRow}>
          <View style={styles.toggleInfo}>
            <Text style={styles.toggleLabel}>Full tunnel</Text>
            <Text style={styles.toggleHint}>Route all traffic through VPN</Text>
          </View>
          <Switch
            value={fullTunnel}
            onValueChange={setFullTunnel}
            trackColor={{ false: colors.borderHi, true: colors.cyan }}
            thumbColor={fullTunnel ? '#000' : colors.textDim}
          />
        </View>
      </View>

      {error ? <Text style={styles.errorMsg}>{error}</Text> : null}

      <TouchableOpacity style={[styles.btn, styles.btnPrimary]} onPress={handleConnect} disabled={busy}>
        {busy
          ? <ActivityIndicator color="#000" />
          : <Text style={[styles.btnText, { color: '#000' }]}>Connect</Text>}
      </TouchableOpacity>
    </ScrollView>
  );
}

function Field({ label, value, onChange, placeholder, secure, mono }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; secure?: boolean; mono?: boolean;
}) {
  return (
    <View style={fieldStyles.group}>
      <Text style={fieldStyles.label}>{label}</Text>
      <TextInput
        style={[fieldStyles.input, mono && { fontFamily: 'monospace' }]}
        value={value}
        onChangeText={onChange}
        placeholder={placeholder}
        placeholderTextColor={colors.textFaint}
        secureTextEntry={secure}
        autoCapitalize="none"
        autoCorrect={false}
      />
    </View>
  );
}

const fieldStyles = StyleSheet.create({
  group: { marginBottom: 14 },
  label: {
    fontSize: 10, fontWeight: '600', color: colors.textDim,
    letterSpacing: 0.5, marginBottom: 6, textTransform: 'uppercase',
  },
  input: {
    backgroundColor: colors.bgPanel,
    borderWidth: 1, borderColor: colors.border, borderRadius: 8,
    color: colors.text, fontSize: 13, paddingHorizontal: 12, paddingVertical: 10,
  },
});

const styles = StyleSheet.create({
  page:    { flex: 1, backgroundColor: colors.bgDeep },
  content: { padding: 16, gap: 14 },
  card: {
    backgroundColor: colors.bgCard, borderRadius: 12,
    borderWidth: 1, borderColor: colors.border, padding: 16,
  },
  cardTitle: {
    fontSize: 13, fontWeight: '700', color: colors.text, marginBottom: 14,
  },
  toggleRow: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
  },
  toggleInfo: { flex: 1 },
  toggleLabel: { fontSize: 13, fontWeight: '600', color: colors.text },
  toggleHint:  { fontSize: 11, color: colors.textDim, marginTop: 2 },
  btn: {
    borderRadius: 10, padding: 14, alignItems: 'center', justifyContent: 'center',
    marginHorizontal: 16,
  },
  btnPrimary: { backgroundColor: colors.cyan },
  btnDanger:  { backgroundColor: colors.red, marginTop: 12 },
  btnText:    { fontSize: 14, fontWeight: '700', color: '#fff' },
  runningRow: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 16 },
  runningDot: {
    width: 10, height: 10, borderRadius: 5, backgroundColor: colors.green,
  },
  runningText: { fontSize: 14, color: colors.text, fontWeight: '600' },
  errorMsg: {
    fontSize: 12, color: colors.red, backgroundColor: 'rgba(255,68,102,0.08)',
    borderWidth: 1, borderColor: 'rgba(255,68,102,0.2)', borderRadius: 8,
    padding: 12, marginHorizontal: 16,
  },
});
