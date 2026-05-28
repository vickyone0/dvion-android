import React from 'react';
import { StatusBar, View, Text, StyleSheet } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { colors } from './theme';
import { useVpn } from './hooks/useVpn';
import StatusScreen  from './screens/StatusScreen';
import ConnectScreen from './screens/ConnectScreen';
import KeysScreen    from './screens/KeysScreen';
import LogsScreen    from './screens/LogsScreen';

const Tab = createBottomTabNavigator();

function TabIcon({ symbol, focused }: { symbol: string; focused: boolean }) {
  return (
    <Text style={{ fontSize: 18, color: focused ? colors.cyan : colors.textDim }}>
      {symbol}
    </Text>
  );
}

export default function App() {
  const { status, logs, connect, disconnect, generateKey, clearLogs } = useVpn();

  return (
    <SafeAreaProvider>
      <StatusBar barStyle="light-content" backgroundColor={colors.bgCard} />
      <NavigationContainer
        theme={{
          dark: true,
          colors: {
            primary:        colors.cyan,
            background:     colors.bgDeep,
            card:           colors.bgCard,
            text:           colors.text,
            border:         colors.border,
            notification:   colors.red,
          },
          fonts: {
            regular: { fontFamily: 'sans-serif', fontWeight: 'normal' },
            medium:  { fontFamily: 'sans-serif', fontWeight: '500'    },
            bold:    { fontFamily: 'sans-serif', fontWeight: '700'    },
            heavy:   { fontFamily: 'sans-serif', fontWeight: '900'    },
          },
        }}
      >
        <View style={styles.header}>
          <Text style={styles.logoText}>◈ dvion</Text>
          <View style={[styles.statusDot, status.running && styles.statusDotActive]} />
          <Text style={styles.badge}>ML-KEM-768 + X25519</Text>
        </View>

        <Tab.Navigator
          screenOptions={{
            headerShown: false,
            tabBarStyle: { backgroundColor: colors.bgCard, borderTopColor: colors.border },
            tabBarActiveTintColor:   colors.cyan,
            tabBarInactiveTintColor: colors.textDim,
            tabBarLabelStyle: { fontSize: 11, fontWeight: '600', marginBottom: 2 },
          }}
        >
          <Tab.Screen
            name="Status"
            options={{ tabBarIcon: ({ focused }) => <TabIcon symbol="◉" focused={focused} /> }}
          >
            {() => <StatusScreen status={status} />}
          </Tab.Screen>

          <Tab.Screen
            name="Connect"
            options={{ tabBarIcon: ({ focused }) => <TabIcon symbol="⟳" focused={focused} /> }}
          >
            {() => <ConnectScreen status={status} onConnect={connect} onDisconnect={disconnect} />}
          </Tab.Screen>

          <Tab.Screen
            name="Keys"
            options={{ tabBarIcon: ({ focused }) => <TabIcon symbol="⌗" focused={focused} /> }}
          >
            {() => <KeysScreen generateKey={generateKey} />}
          </Tab.Screen>

          <Tab.Screen
            name="Logs"
            options={{
              tabBarBadge: logs.length > 0 ? (logs.length > 999 ? '999+' : logs.length) : undefined,
              tabBarIcon: ({ focused }) => <TabIcon symbol="≡" focused={focused} />,
            }}
          >
            {() => <LogsScreen logs={logs} onClear={clearLogs} />}
          </Tab.Screen>
        </Tab.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  header: {
    backgroundColor: colors.bgCard,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 10,
    gap: 8,
  },
  logoText: {
    fontSize: 18, fontWeight: '700', letterSpacing: 3, color: colors.text, flex: 1,
  },
  statusDot: {
    width: 8, height: 8, borderRadius: 4, backgroundColor: colors.textFaint,
  },
  statusDotActive: { backgroundColor: colors.green },
  badge: {
    fontSize: 8, color: colors.purple, fontFamily: 'monospace', letterSpacing: 0.5,
  },
});
