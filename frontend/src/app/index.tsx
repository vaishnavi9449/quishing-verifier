import React, { useState, useRef } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Alert, ScrollView } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import axios from 'axios';

const BACKEND_URL = 'https://quishing-verifier-production.up.railway.app';

export default function QRScanner() {
  const [permission, requestPermission] = useCameraPermissions();
  const [scannedURL, setScannedURL] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isScanning, setIsScanning] = useState(true);
  const cameraRef = useRef(null);

  if (!permission) {
    return <View />;
  }

  if (!permission.granted) {
    return (
      <View style={styles.container}>
        <Text>We need camera permission</Text>
        <TouchableOpacity onPress={requestPermission}>
          <Text style={styles.button}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const analyzeURL = async (url) => {
    setScannedURL(url);
    setIsScanning(false);
    
    try {
      const response = await axios.post(`${BACKEND_URL}/analyze/full`, { url });
      setAnalysisResult(response.data);
      
      if (response.data.riskScore >= 70) {
        Alert.alert('⚠️ HIGH RISK', `Score: ${response.data.riskScore}/100 - MALICIOUS`);
      } else if (response.data.riskScore >= 40) {
        Alert.alert('⚠️ MEDIUM RISK', `Score: ${response.data.riskScore}/100 - SUSPICIOUS`);
      } else {
        Alert.alert('✅ SAFE', `Score: ${response.data.riskScore}/100 - LEGITIMATE`);
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to analyze URL: ' + error.message);
    }
  };

  const handleBarCodeScanned = ({ data }) => {
    if (isScanning) {
      analyzeURL(data);
    }
  };

  const resetScanner = () => {
    setScannedURL('');
    setAnalysisResult(null);
    setIsScanning(true);
  };

  return (
    <View style={styles.container}>
      {isScanning ? (
        <>
          <CameraView
            style={styles.camera}
            onBarcodeScanned={handleBarCodeScanned}
            barcodeScannerSettings={{
              barcodeTypes: ['qr'],
            }}
          />
          <Text style={styles.instruction}>Point camera at QR code</Text>
        </>
      ) : (
        <ScrollView style={styles.resultContainer}>
          <Text style={styles.urlText}>URL: {scannedURL}</Text>
          {analysisResult && (
            <>
              <Text style={styles.scoreText}>Risk Score: {analysisResult.riskScore}/100</Text>
              <Text style={styles.detailsText}>{JSON.stringify(analysisResult, null, 2)}</Text>
            </>
          )}
        </ScrollView>
      )}
      
      <TouchableOpacity style={styles.button} onPress={resetScanner}>
        <Text style={styles.buttonText}>Scan Again</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000',
  },
  camera: {
    flex: 1,
  },
  instruction: {
    position: 'absolute',
    bottom: 100,
    left: 0,
    right: 0,
    textAlign: 'center',
    color: '#fff',
    fontSize: 18,
  },
  resultContainer: {
    flex: 1,
    padding: 20,
    backgroundColor: '#1a1a1a',
  },
  urlText: {
    color: '#fff',
    marginBottom: 10,
    fontSize: 14,
  },
  scoreText: {
    color: '#0f0',
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  detailsText: {
    color: '#aaa',
    fontSize: 12,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 15,
    margin: 10,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
});