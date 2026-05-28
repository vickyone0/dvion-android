import React, { useState, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  ScrollView, ActivityIndicator, Alert, Clipboard,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { colors } from '../theme';

const KEYS_STORAGE = 'dvion_keys';

interface Props {
  generateKey: () => Promise<string>;
}

export default function KeysScreen({ generateKey }: Props) {
  const [keys,    setKeys]    = useState<string[]>([]);
  const [busy,    setBusy]    = useState(false);
  const [copied,  setCopied]  = useState<string | null>(null);

  useEffect(() => {
    AsyncStorage.getItem(KEYS_STORAGE)
      .then(raw => { if (raw) setKeys(JSON.parse(raw)); })
      .catch(() => {});
  }, []);

  const persist = (list: string[]) => {
    setKeys(list);
    AsyncStorage.setItem(KEYS_STORAGE, JSON.stringify(list)).catch(() => {});
  };

  const handleGenerate = async () => {
    setBusy(true);
    try {
      const key = await generateKey();
      persist([...keys, key]);
    } catch (e: any) {
      Alert.alert('Error', e?.message ?? 'Failed to generate key');
    } finally {
      setBusy(false);
    }
  };

  const handleCopy = (key: string) => {
    Clipboard.setString(key);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleRevoke = (key: string) => {
    Alert.alert('Revoke Key', 'Remove this key from the device?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Revoke', style: 'destructive', onPress: () => persist(keys.filter(k => k !== key)) },
    ]);
  };

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content}>
      <TouchableOpacity style={[styles.btn, styles.btnPrimary]} onPress={handleGenerate} disabled={busy}>
        {busy
          ? <ActivityIndicator color="#000" />
          : <Text style={[styles.btnText, { color: '#000' }]}>+ Generate Key</Text>}
      </TouchableOpacity>

      {keys.length === 0 && (
        <Text style={styles.emptyMsg}>No keys yet. Generate one to get started.</Text>
      )}

      {keys.map(key => (
        <View key={key} style={styles.keyRow}>
          <Text style={styles.keyValue} numberOfLines={1}>{key}</Text>
          <View style={styles.keyActions}>
            <TouchableOpacity
              style={[styles.actionBtn, copied === key && styles.actionBtnSuccess]}
              onPress={() => handleCopy(key)}
            >
              <Text style={[styles.actionText, copied === key && { color: colors.green }]}>
                {copied === key ? 'Copied' : 'Copy'}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.actionBtn, styles.actionBtnDanger]} onPress={() => handleRevoke(key)}>
              <Text style={[styles.actionText, { color: colors.red }]}>Revoke</Text>
            </TouchableOpacity>
          </View>
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page:    { flex: 1, backgroundColor: colors.bgDeep },
  content: { padding: 16, gap: 10 },

  btn: { borderRadius: 10, padding: 14, alignItems: 'center', justifyContent: 'center' },
  btnPrimary: { backgroundColor: colors.cyan, marginBottom: 6 },
  btnText: { fontSize: 14, fontWeight: '700' },

  emptyMsg: {
    fontSize: 13, color: colors.textDim, textAlign: 'center', paddingVertical: 32,
  },

  keyRow: {
    backgroundColor: colors.bgCard,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 12,
    gap: 10,
  },
  keyValue: {
    fontSize: 12, color: colors.text, fontFamily: 'monospace', flex: 1,
  },
  keyActions: { flexDirection: 'row', gap: 8, justifyContent: 'flex-end' },
  actionBtn: {
    paddingHorizontal: 12, paddingVertical: 6,
    backgroundColor: colors.bgPanel, borderRadius: 6,
    borderWidth: 1, borderColor: colors.border,
  },
  actionBtnSuccess: { borderColor: colors.green },
  actionBtnDanger:  { borderColor: 'rgba(255,68,102,0.3)' },
  actionText: { fontSize: 11, fontWeight: '600', color: colors.textDim },
});
