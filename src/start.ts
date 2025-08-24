import app from './server.js';
import { GeoAnalyzer } from './detection/analyzers/GeoAnalyzer.js';

const PORT = process.env.PORT || 3000;

// Initialize GeoAnalyzer databases on server start
async function initializeServer() {
  try {
    console.log('Initializing GeoAnalyzer databases...');
    await GeoAnalyzer.ensureDatabases();
    console.log('GeoAnalyzer databases initialized successfully');
  } catch (error) {
    console.error('Failed to initialize GeoAnalyzer databases:', error);
    console.log('Server will continue with GeoAnalyzer in simulation mode');
  }

  app.listen(PORT, () => {
    console.log(`Boomberman server running on port ${PORT}`);
  });
}

initializeServer().catch(console.error);
