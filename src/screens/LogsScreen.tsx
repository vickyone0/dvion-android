import React, { useRef, useEffect } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, FlatList } from 'react-native';
import { colors } from '../theme';

interface Props {
  logs:    string[];
  onClear: () => void;
}

function logClass(line: string) {
  if (/\b(error|err|fail|panic)\b/i.test(line))  return styles.logErr;
  if (/\b(info|connected|started|ok)\b/i.test(line)) return styles.logInfo;
  return null;
}

export default function LogsScreen({ logs, onClear }: Props) {
  const listRef = useRef<FlatList>(null);

  useEffect(() => {
    if (logs.length > 0) {
      listRef.current?.scrollToEnd({ animated: true });
    }
  }, [logs.length]);

  return (
    <View style={styles.page}>
      <View style={styles.header}>
        <View>
          <Text style={styles.title}>Logs</Text>
          <Text style={styles.subtitle}>{logs.length} entries</Text>
        </View>
        <TouchableOpacity style={styles.clearBtn} onPress={onClear} disabled={logs.length === 0}>
          <Text style={[styles.clearText, logs.length === 0 && styles.clearDisabled]}>Clear</Text>
        </TouchableOpacity>
      </View>

      {logs.length === 0 ? (
        <View style={styles.emptyWrap}>
          <Text style={styles.emptyMsg}>No logs yet. Connect to a server to see output.</Text>
        </View>
      ) : (
        <FlatList
          ref={listRef}
          data={logs}
          keyExtractor={(_, i) => String(i)}
          style={styles.output}
          renderItem={({ item, index }) => (
            <Text style={[styles.logLine, logClass(item)]}>
              <Text style={styles.logNum}>{String(index + 1).padStart(4, ' ')}  </Text>
              {item}
            </Text>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  page:   { flex: 1, backgroundColor: colors.bgDeep },
  header: {
    flexDirection: 'row', alignItems: 'flex-end', justifyContent: 'space-between',
    padding: 16, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  title:    { fontSize: 16, fontWeight: '700', color: colors.text },
  subtitle: { fontSize: 11, color: colors.textDim, marginTop: 2 },
  clearBtn: {
    paddingHorizontal: 12, paddingVertical: 6,
    backgroundColor: colors.bgPanel, borderRadius: 6,
    borderWidth: 1, borderColor: colors.border,
  },
  clearText:    { fontSize: 12, fontWeight: '600', color: colors.textDim },
  clearDisabled: { color: colors.textFaint },

  output: { flex: 1, backgroundColor: '#040408', padding: 8 },
  logLine: {
    fontFamily: 'monospace', fontSize: 11.5, lineHeight: 20,
    color: '#7878a8', paddingHorizontal: 4,
  },
  logErr:  { color: '#ff6680' },
  logInfo: { color: '#7ad4a0' },
  logNum:  { color: colors.textFaint },

  emptyWrap: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  emptyMsg:  { fontSize: 13, color: colors.textFaint, textAlign: 'center', paddingHorizontal: 32 },
});
