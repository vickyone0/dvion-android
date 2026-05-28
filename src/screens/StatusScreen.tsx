import React from 'react';
import { View, Text, StyleSheet, ScrollView } from 'react-native';
import { colors } from '../theme';
import { VpnStatus } from '../hooks/useVpn';

function fmtUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

export default function StatusScreen({ status }: { status: VpnStatus }) {
  const connected = status.running;

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content}>
      <View style={[styles.heroCard, connected && styles.heroCardActive]}>
        <View style={[styles.heroRing, connected && styles.heroRingActive]}>
          <View style={[styles.heroDot, connected && styles.heroDotActive]} />
        </View>
        <View>
          <Text style={[styles.heroLabel, connected && styles.heroLabelActive]}>
            {connected ? 'CONNECTED' : 'DISCONNECTED'}
          </Text>
          {status.mode && (
            <Text style={styles.heroMode}>{status.mode} mode</Text>
          )}
        </View>
      </View>

      <View style={styles.statsGrid}>
        <View style={[styles.card, styles.statCard]}>
          <Text style={styles.statLabel}>UPTIME</Text>
          <Text style={styles.statValue}>{fmtUptime(status.uptime_secs)}</Text>
        </View>
        <View style={[styles.card, styles.statCard]}>
          <Text style={styles.statLabel}>PROTOCOL</Text>
          <Text style={styles.statValue}>QUIC</Text>
        </View>
        <View style={[styles.card, styles.statCard]}>
          <Text style={styles.statLabel}>KEM</Text>
          <Text style={styles.statValue}>ML-KEM-768</Text>
        </View>
        <View style={[styles.card, styles.statCard]}>
          <Text style={styles.statLabel}>CIPHER</Text>
          <Text style={styles.statValue}>CHA20-P1305</Text>
        </View>
      </View>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Security Info</Text>
        {[
          ['Key Exchange', 'ML-KEM-768 + X25519'],
          ['Transport',   'QUIC / TLS 1.3'],
          ['Encryption',  'ChaCha20-Poly1305'],
          ['Auth',        'AEAD + Pre-shared key'],
        ].map(([label, value]) => (
          <View key={label} style={styles.infoRow}>
            <Text style={styles.infoLabel}>{label}</Text>
            <Text style={styles.infoValue}>{value}</Text>
          </View>
        ))}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page:    { flex: 1, backgroundColor: colors.bgDeep },
  content: { padding: 16, gap: 12 },

  heroCard: {
    backgroundColor: colors.bgCard,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 24,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 20,
  },
  heroCardActive: { borderColor: colors.green },

  heroRing: {
    width: 56,
    height: 56,
    borderRadius: 28,
    borderWidth: 2,
    borderColor: colors.textFaint,
    alignItems: 'center',
    justifyContent: 'center',
  },
  heroRingActive: { borderColor: colors.green },

  heroDot: {
    width: 18,
    height: 18,
    borderRadius: 9,
    backgroundColor: colors.textFaint,
  },
  heroDotActive: { backgroundColor: colors.green },

  heroLabel: {
    fontSize: 20,
    fontWeight: '800',
    letterSpacing: 3,
    color: colors.textFaint,
  },
  heroLabelActive: { color: colors.green },

  heroMode: {
    fontSize: 12,
    color: colors.textDim,
    marginTop: 4,
    textTransform: 'capitalize',
  },

  statsGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: 10 },
  card: {
    backgroundColor: colors.bgCard,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 16,
  },
  statCard: { flex: 1, minWidth: '45%' },
  statLabel: {
    fontSize: 10,
    fontWeight: '600',
    color: colors.textDim,
    letterSpacing: 0.5,
    marginBottom: 6,
  },
  statValue: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.cyan,
    fontFamily: 'monospace',
  },

  sectionTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: colors.text,
    marginBottom: 14,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 7,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  infoLabel: { fontSize: 12, color: colors.textDim },
  infoValue: {
    fontSize: 12,
    color: colors.text,
    fontFamily: 'monospace',
    fontWeight: '600',
  },
});
