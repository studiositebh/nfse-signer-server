/**
 * NFS-e Signer Server
 * Servidor Node.js para assinatura digital e transmissão de NFS-e para Sefin Nacional
 * 
 * Este servidor é necessário porque:
 * 1. Supabase Edge Functions não suportam mTLS (mutual TLS) exigido pela Sefin
 * 2. Bibliotecas de assinatura XML como xml-crypto não funcionam em Deno
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { emitirNfse, consultarNfse, cancelarNfse } = require('./services/nfseService');
const { healthCheck } = require('./services/healthService');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware de segurança
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));
app.use(express.json({ limit: '10mb' }));

// Middleware de autenticação por API Key
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const expectedKey = process.env.API_SECRET_KEY;
  
  if (!expectedKey) {
    console.error('[AUTH] API_SECRET_KEY não configurada');
    return res.status(500).json({ error: 'Servidor mal configurado' });
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    console.warn('[AUTH] Tentativa de acesso não autorizada');
    return res.status(401).json({ error: 'Não autorizado' });
  }
  
  next();
};

// Health check (público)
app.get('/health', async (req, res) => {
  const status = await healthCheck();
  res.status(status.healthy ? 200 : 503).json(status);
});

// Rotas protegidas
app.use('/api', authenticateApiKey);

/**
 * POST /api/emitir
 * Emite uma NFS-e para a Sefin Nacional
 */
app.post('/api/emitir', async (req, res) => {
  console.log('[EMITIR] Iniciando emissão de NFS-e');
  
  try {
    const { pfxBase64, pfxPassword, dps, ambiente } = req.body;
    
    if (!pfxBase64 || !pfxPassword || !dps) {
      return res.status(400).json({
        success: false,
        error: 'Parâmetros obrigatórios: pfxBase64, pfxPassword, dps'
      });
    }
    
    const result = await emitirNfse({
      pfxBase64,
      pfxPassword,
      dps,
      ambiente: ambiente || process.env.NFSE_AMBIENTE || 'homologacao'
    });
    
    console.log('[EMITIR] Resultado:', result.success ? 'Sucesso' : 'Falha');
    res.status(result.success ? 200 : 400).json(result);
    
  } catch (error) {
    console.error('[EMITIR] Erro:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro interno ao processar emissão',
      details: error.message
    });
  }
});

/**
 * POST /api/consultar
 * Consulta uma NFS-e pela chave de acesso
 */
app.post('/api/consultar', async (req, res) => {
  console.log('[CONSULTAR] Iniciando consulta de NFS-e');
  
  try {
    const { pfxBase64, pfxPassword, chaveAcesso, ambiente } = req.body;
    
    if (!pfxBase64 || !pfxPassword || !chaveAcesso) {
      return res.status(400).json({
        success: false,
        error: 'Parâmetros obrigatórios: pfxBase64, pfxPassword, chaveAcesso'
      });
    }
    
    const result = await consultarNfse({
      pfxBase64,
      pfxPassword,
      chaveAcesso,
      ambiente: ambiente || process.env.NFSE_AMBIENTE || 'homologacao'
    });
    
    res.status(result.success ? 200 : 400).json(result);
    
  } catch (error) {
    console.error('[CONSULTAR] Erro:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro interno ao consultar NFS-e',
      details: error.message
    });
  }
});

/**
 * POST /api/cancelar
 * Cancela uma NFS-e
 */
app.post('/api/cancelar', async (req, res) => {
  console.log('[CANCELAR] Iniciando cancelamento de NFS-e');
  
  try {
    const { pfxBase64, pfxPassword, chaveAcesso, motivoCancelamento, ambiente } = req.body;
    
    if (!pfxBase64 || !pfxPassword || !chaveAcesso) {
      return res.status(400).json({
        success: false,
        error: 'Parâmetros obrigatórios: pfxBase64, pfxPassword, chaveAcesso'
      });
    }
    
    const result = await cancelarNfse({
      pfxBase64,
      pfxPassword,
      chaveAcesso,
      motivoCancelamento: motivoCancelamento || 'Cancelamento solicitado pelo emitente',
      ambiente: ambiente || process.env.NFSE_AMBIENTE || 'homologacao'
    });
    
    res.status(result.success ? 200 : 400).json(result);
    
  } catch (error) {
    console.error('[CANCELAR] Erro:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erro interno ao cancelar NFS-e',
      details: error.message
    });
  }
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] NFS-e Signer Server rodando na porta ${PORT}`);
  console.log(`[SERVER] Ambiente: ${process.env.NFSE_AMBIENTE || 'homologacao'}`);
});
