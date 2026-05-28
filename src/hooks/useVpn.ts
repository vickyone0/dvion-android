import { useState, useEffect, useCallback } from 'react';
import { NativeModules, NativeEventEmitter } from 'react-native';

const { DvionVpnModule } = NativeModules;
const emitter = new NativeEventEmitter(DvionVpnModule);

export interface VpnStatus {
  running: boolean;
  mode: string | null;
  uptime_secs: number;
}

export function useVpn() {
  const [status, setStatus]  = useState<VpnStatus>({ running: false, mode: null, uptime_secs: 0 });
  const [logs,   setLogs]    = useState<string[]>([]);

  useEffect(() => {
    const s = emitter.addListener('vpn-status', (payload: VpnStatus) => setStatus(payload));
    const l = emitter.addListener('vpn-log',    (line: string)       => setLogs(prev => [...prev.slice(-999), line]));
    DvionVpnModule.getStatus().then(setStatus).catch(() => {});
    return () => { s.remove(); l.remove(); };
  }, []);

  const connect = useCallback(
    (server: string, authKey: string, fullTunnel: boolean, fingerprint?: string) =>
      DvionVpnModule.connect(server, authKey, fullTunnel, fingerprint ?? null) as Promise<void>,
    [],
  );

  const disconnect = useCallback(
    () => DvionVpnModule.disconnect() as Promise<void>,
    [],
  );

  const generateKey = useCallback(
    () => DvionVpnModule.generateKey() as Promise<string>,
    [],
  );

  const clearLogs = useCallback(() => setLogs([]), []);

  return { status, logs, connect, disconnect, generateKey, clearLogs };
}
