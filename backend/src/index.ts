import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { validateAndParseCSV } from './csv-validator';
import { analyzeTransactions } from './detection-engine';
import { generateSampleData } from './sample-data';
import { DetectionMode } from './types';

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Multer for file uploads (store in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// POST /api/analyze - Upload CSV file and get analysis results
app.post('/api/analyze', upload.single('file'), (req, res) => {
  try {
    // Parse optional detection mode from query string (?mode=fan-in etc.)
    const VALID_MODES: DetectionMode[] = ['all', 'fan-in', 'fan-out', 'cycles', 'shell'];
    const modeParam = (req.query.mode as string || 'all').toLowerCase() as DetectionMode;
    const mode: DetectionMode = VALID_MODES.includes(modeParam) ? modeParam : 'all';

    let csvContent: string;

    if (req.file) {
      // File uploaded via multipart form
      csvContent = req.file.buffer.toString('utf-8');
    } else if (req.body?.csvContent) {
      // CSV content sent as JSON body
      csvContent = req.body.csvContent;
    } else {
      res.status(400).json({
        success: false,
        error: 'No CSV file or content provided. Send a file via multipart form or csvContent in JSON body.',
      });
      return;
    }

    // Validate and parse CSV
    const validation = validateAndParseCSV(csvContent);

    if (!validation.success || validation.transactions.length === 0) {
      res.status(400).json({
        success: false,
        validation: {
          errors: validation.errors,
          warnings: validation.warnings,
        },
      });
      return;
    }

    // Run detection engine with selected mode
    const result = analyzeTransactions(validation.transactions, mode);

    res.json({
      success: true,
      validation: {
        errors: validation.errors,
        warnings: validation.warnings,
        transactionCount: validation.transactions.length,
      },
      analysis: result,
    });
  } catch (error: any) {
    console.error('Analysis error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during analysis',
      message: error.message,
    });
  }
});

// POST /api/validate - Validate CSV without running analysis
app.post('/api/validate', upload.single('file'), (req, res) => {
  try {
    let csvContent: string;

    if (req.file) {
      csvContent = req.file.buffer.toString('utf-8');
    } else if (req.body?.csvContent) {
      csvContent = req.body.csvContent;
    } else {
      res.status(400).json({
        success: false,
        error: 'No CSV file or content provided.',
      });
      return;
    }

    const validation = validateAndParseCSV(csvContent);

    res.json({
      success: validation.success,
      transactionCount: validation.transactions.length,
      errors: validation.errors,
      warnings: validation.warnings,
    });
  } catch (error: any) {
    console.error('Validation error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during validation',
      message: error.message,
    });
  }
});

// GET /api/sample-data - Generate sample data and return analysis
app.get('/api/sample-data', (_req, res) => {
  try {
    // Parse optional detection mode from query string
    const VALID_MODES: DetectionMode[] = ['all', 'fan-in', 'fan-out', 'cycles', 'shell'];
    const modeParam = (_req.query.mode as string || 'all').toLowerCase() as DetectionMode;
    const mode: DetectionMode = VALID_MODES.includes(modeParam) ? modeParam : 'all';

    const sampleData = generateSampleData();
    const result = analyzeTransactions(sampleData, mode);

    res.json({
      success: true,
      analysis: result,
    });
  } catch (error: any) {
    console.error('Sample data error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error generating sample data',
      message: error.message,
    });
  }
});

// ─── START SERVER ────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔍 Financial Forensics Engine - Backend API`);
  console.log(`   Server running on http://localhost:${PORT}`);
  console.log(`\n   Endpoints:`);
  console.log(`   GET  /api/health       - Health check`);
  console.log(`   POST /api/analyze      - Upload CSV & analyze`);
  console.log(`   POST /api/validate     - Validate CSV only`);
  console.log(`   GET  /api/sample-data  - Analyze sample data\n`);
});
