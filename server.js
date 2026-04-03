import express from 'express';
import { scanUrl } from './scanner/index.js';

const app = express();
app.use(express.json());
app.use(express.static('public'));

app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try {
    const result = await scanUrl(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Scan failed', message: err.message });
  }
});

app.listen(3000, () => console.log('Scanner running at http://localhost:3000'));
