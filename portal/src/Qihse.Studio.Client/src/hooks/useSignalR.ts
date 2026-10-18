import { useEffect, useState } from 'react';
import * as signalR from '@microsoft/signalr';
import type { TelemetryFrame } from '../types';

export function useSignalR(apiToken: string) {
  const [telemetry, setTelemetry] = useState<TelemetryFrame | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  useEffect(() => {
    if (!apiToken) return;
    // Connect to ASP.NET Core SignalR TelemetryHub
    const connection = new signalR.HubConnectionBuilder()
      .withUrl('/hub/telemetry', { accessTokenFactory: () => apiToken })
      .withAutomaticReconnect([0, 2000, 5000, 10000])
      .configureLogging(signalR.LogLevel.Warning)
      .build();

    connection.on('ReceiveTelemetry', (frame: TelemetryFrame) => {
      setTelemetry(frame);
    });

    connection
      .start()
      .then(() => {
        setIsConnected(true);
        setConnectionError(null);
      })
      .catch((err) => {
        console.warn('SignalR initial connection failed, falling back to REST snapshot:', err);
        setIsConnected(false);
        setConnectionError(err.toString());
      });

    connection.onreconnecting(() => setIsConnected(false));
    connection.onreconnected(() => setIsConnected(true));
    connection.onclose(() => setIsConnected(false));

    // Fallback REST fetch if SignalR takes time
    fetch('/api/telemetry/snapshot', { headers: { Authorization: `Bearer ${apiToken}` } })
      .then((res) => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
      .then((data: TelemetryFrame) => setTelemetry(data))
      .catch(() => {});

    return () => {
      connection.stop();
    };
  }, [apiToken]);

  return { telemetry, isConnected, connectionError };
}
