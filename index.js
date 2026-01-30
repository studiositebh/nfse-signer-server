/**
 * NFS-e Signer Server - Padrão Nacional
 * Certificado A1 carregado via variável de ambiente NFSE_CERT_BASE64
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const { create } = require('xmlbuilder2');
const https = require('https');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================
// MIDDLEWARE
// ============================================
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// Autenticação via Header Authorization
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const expectedKey = process.env.API_SECRET_KEY;
  
  if (!expectedKey) {
    console.error('[AUTH] API_SECRET_KEY não configurada');
    return res.status(500).json({ error: 'Servidor mal configurado' });
  }
  
  // Aceita "Bearer <token>" ou apenas "<token>"
  const token = authHeader?.replace('Bearer ', '');
  
  if (!token || token !== expectedKey) {
    console.warn('[AUTH] Tentativa de acesso não autorizada');
    return res.status(401).json({ error: 'Não autorizado' });
  }
  
  next();
};

// ============================================
// CARREGAMENTO DO CERTIFICADO
// ============================================
let cachedCertificate = null;

function loadCertificateFromEnv() {
  if (cachedCertificate) return cachedCertificate;
  
  const certBase64 = process.env.NFSE_CERT_BASE64;
  const certPassword = process.env.NFSE_CERT_PASSWORD;
  
  if (!certBase64 || !certPassword) {
    throw new Error('Variáveis NFSE_CERT_BASE64 e NFSE_CERT_PASSWORD são obrigatórias');
  }
  
  console.log('[CERT] Carregando certificado da variável de ambiente...');
  
  // Converte Base64 para Buffer binário
  const pfxBuffer = Buffer.from(certBase64, 'base64');
  
  // Converte para formato DER (ArrayBuffer)
  const pfxDer = forge.util.createBuffer(pfxBuffer.toString('binary'));
  
  // Decodifica o PFX usando node-forge
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, certPassword);
  
  // Extrai a chave privada
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
  
  if (!keyBag || !keyBag.key) {
    throw new Error('Chave privada não encontrada no certificado');
  }
  
  // Extrai o certificado
  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certBag = certBags[forge.pki.oids.certBag]?.[0];
  
  if (!certBag || !certBag.cert) {
    throw new Error('Certificado não encontrado no arquivo PFX');
  }
  
  // Converte para formato PEM
  const privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);
  const certificatePem = forge.pki.certificateToPem(certBag.cert);
  
  // Extrai informações do certificado
  const cert = certBag.cert;
  const subject = cert.subject.attributes.map(attr => 
    `${attr.shortName}=${attr.value}`
  ).join(', ');
  
  const validFrom = cert.validity.notBefore;
  const validUntil = cert.validity.notAfter;
  
  // Verifica validade
  const now = new Date();
  if (now < validFrom || now > validUntil) {
    throw new Error(`Certificado expirado ou ainda não válido. Válido de ${validFrom} até ${validUntil}`);
  }
  
  console.log('[CERT] Certificado carregado com sucesso');
  console.log('[CERT] Titular:', subject);
  console.log('[CERT] Válido até:', validUntil);
  
  cachedCertificate = {
    privateKeyPem,
    certificatePem,
    subject,
    validFrom,
    validUntil,
    certBase64: forge.util.encode64(forge.asn1.toDer(
      forge.pki.certificateToAsn1(cert)
    ).getBytes())
  };
  
  return cachedCertificate;
}

// ============================================
// ASSINATURA XML (Padrão Nacional - XMLDSig)
// ============================================
function signXml(xmlContent, privateKeyPem, certificatePem) {
  // Remove header XML se existir para processamento
  const xmlWithoutHeader = xmlContent.replace(/<\?xml[^?]*\?>\s*/g, '');
  
  // Encontra o elemento a ser assinado (infDPS)
  const idMatch = xmlWithoutHeader.match(/Id="([^"]+)"/);
  if (!idMatch) {
    throw new Error('Elemento com atributo Id não encontrado no XML');
  }
  const referenceUri = `#${idMatch[1]}`;
  
  // Configura a assinatura
  const sig = new SignedXml();
  
  // Configura o algoritmo de assinatura
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  
  // Adiciona a referência ao elemento a ser assinado
  sig.addReference(
    referenceUri,
    [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    ],
    'http://www.w3.org/2001/04/xmlenc#sha256'
  );
  
  // Configura a chave de assinatura
  sig.signingKey = privateKeyPem;
  
  // Adiciona o certificado X509
  const certContent = certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  
  sig.keyInfoProvider = {
    getKeyInfo: () => `<X509Data><X509Certificate>${certContent}</X509Certificate></X509Data>`
  };
  
  // Calcula a assinatura
  sig.computeSignature(xmlWithoutHeader, {
    location: { reference: `//*[@Id='${idMatch[1]}']`, action: 'append' }
  });
  
  // Retorna o XML assinado com header
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + sig.getSignedXml();
}

// ============================================
// GERAÇÃO DO XML DPS (Padrão Nacional)
// ============================================
function buildDpsXml(data, ambiente) {
  const now = new Date();
  const dhEmi = now.toISOString();
  const dCompet = now.toISOString().split('T')[0];
  
  // Dados do prestador (fixos da empresa)
  const prestador = data.prestador || {};
  const cnpjPrestador = (prestador.cnpj || process.env.PRESTADOR_CNPJ || '').replace(/\D/g, '');
  const imPrestador = (prestador.inscricaoMunicipal || process.env.PRESTADOR_IM || '').replace(/\D/g, '');
  
  // Dados do tomador
  const tomador = data.tomador || {};
  const cpfCnpjTomador = (tomador.cpfCnpj || '').replace(/\D/g, '');
  const nomeTomador = tomador.nome || 'Consumidor';
  
  // Serviço
  const servico = data.servico || {};
  const codigoServico = (servico.codigo || '010302').replace(/\./g, '');
  const descricao = servico.descricao || 'Serviços prestados conforme contrato';
  const codigoMunicipio = servico.codigoMunicipio || process.env.CODIGO_MUNICIPIO || '3106200';
  
  // Valores
  const valorServico = parseFloat(data.valor) || 0;
  
  // Gera identificador único
  const idDPS = `DPS${cnpjPrestador}${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${Date.now()}`;
  
  // Constrói o XML
  const doc = create({ version: '1.0', encoding: 'UTF-8' })
    .ele('DPS', {
      xmlns: 'http://www.sped.fazenda.gov.br/nfse',
      versao: '1.00'
    })
      .ele('infDPS', { Id: idDPS })
        .ele('tpAmb').txt(ambiente === 'producao' ? '1' : '2').up()
        .ele('dhEmi').txt(dhEmi).up()
        .ele('verAplic').txt('NFSE-SIGNER-1.0').up()
        .ele('dCompet').txt(dCompet).up()
        
        // Prestador
        .ele('prest')
          .ele('CNPJ').txt(cnpjPrestador).up()
          .ele('IM').txt(imPrestador).up()
        .up()
        
        // Tomador
        .ele('toma');
  
  // CPF ou CNPJ do tomador
  if (cpfCnpjTomador.length === 11) {
    doc.ele('CPF').txt(cpfCnpjTomador).up();
  } else if (cpfCnpjTomador.length === 14) {
    doc.ele('CNPJ').txt(cpfCnpjTomador).up();
  }
  
  doc.ele('xNome').txt(nomeTomador).up();
  
  // Endereço do tomador
  if (tomador.endereco) {
    const end = tomador.endereco;
    doc.ele('end')
      .ele('endNac')
        .ele('cMun').txt(end.codigoMunicipio || codigoMunicipio).up()
        .ele('CEP').txt((end.cep || '').replace(/\D/g, '')).up()
      .up()
      .ele('xLgr').txt(end.logradouro || '').up()
      .ele('nro').txt(end.numero || 'S/N').up()
      .ele('xBairro').txt(end.bairro || '').up();
    
    if (end.complemento) {
      doc.ele('xCpl').txt(end.complemento).up();
    }
    doc.up();
  }
  
  doc.up(); // Fecha toma
  
  // Serviço
  doc.ele('serv')
    .ele('locPrest')
      .ele('cLocPrestacao').txt(codigoMunicipio).up()
    .up()
    .ele('cServ')
      .ele('cTribNac').txt(codigoServico).up()
      .ele('xDescServ').txt(descricao).up()
    .up()
  .up();
  
  // Valores
  doc.ele('valores')
    .ele('vServPrest')
      .ele('vServ').txt(valorServico.toFixed(2)).up()
    .up()
    .ele('trib')
      .ele('tribMun')
        .ele('tribISSQN').txt('1').up()
        .ele('cLocIncid').txt(codigoMunicipio).up()
        .ele('pAliq').txt('0.00').up()
        .ele('tpRetISSQN').txt('1').up()
      .up()
    .up()
  .up();
  
  doc.up(); // Fecha infDPS
  doc.up(); // Fecha DPS
  
  return doc.end({ prettyPrint: true });
}

// ============================================
// COMUNICAÇÃO COM SEFIN NACIONAL
// ============================================
const SEFIN_URLS = {
  producao: 'https://sefin.nfse.gov.br/sefinnacional',
  homologacao: 'https://sefin.producaorestrita.nfse.gov.br/SefinNacional'
};

async function enviarParaSefin(signedXml, privateKeyPem, certificatePem, ambiente) {
  const baseUrl = SEFIN_URLS[ambiente] || SEFIN_URLS.homologacao;
  const url = `${baseUrl}/nfse`;
  
  console.log('[SEFIN] Enviando para:', url);
  
  const agent = new https.Agent({
    key: privateKeyPem,
    cert: certificatePem,
    rejectUnauthorized: true,
    keepAlive: true
  });
  
  try {
    const response = await axios.post(url, signedXml, {
      httpsAgent: agent,
      headers: {
        'Content-Type': 'application/xml',
        'Accept': 'application/xml'
      },
      timeout: 60000,
      validateStatus: null
    });
    
    console.log('[SEFIN] Status:', response.status);
    
    return {
      success: response.status >= 200 && response.status < 300,
      status: response.status,
      data: response.data
    };
  } catch (error) {
    console.error('[SEFIN] Erro:', error.message);
    throw error;
  }
}

// ============================================
// ENDPOINTS
// ============================================

// Health check (público)
app.get('/health', (req, res) => {
  const certConfigured = !!(process.env.NFSE_CERT_BASE64 && process.env.NFSE_CERT_PASSWORD);
  
  res.json({
    healthy: true,
    certificateConfigured: certConfigured,
    ambiente: process.env.NFSE_AMBIENTE || 'homologacao',
    timestamp: new Date().toISOString()
  });
});

// Emitir NFS-e (protegido)
app.post('/emitir-nfse', authenticate, async (req, res) => {
  console.log('[EMITIR] Iniciando emissão de NFS-e');
  
  try {
    // Carrega o certificado
    const cert = loadCertificateFromEnv();
    
    // Dados da requisição
    const { tomador, servico, valor, ambiente } = req.body;
    
    if (!tomador || !valor) {
      return res.status(400).json({
        success: false,
        error: 'Parâmetros obrigatórios: tomador, valor'
      });
    }
    
    const ambienteAtual = ambiente || process.env.NFSE_AMBIENTE || 'homologacao';
    
    // Gera o XML da DPS
    console.log('[EMITIR] Gerando XML...');
    const dpsXml = buildDpsXml(req.body, ambienteAtual);
    
    // Assina o XML
    console.log('[EMITIR] Assinando XML...');
    const signedXml = signXml(dpsXml, cert.privateKeyPem, cert.certificatePem);
    
    // Extrai ID da DPS
    const idMatch = signedXml.match(/Id="([^"]+)"/);
    const dpsId = idMatch ? idMatch[1] : null;
    
    console.log('[EMITIR] DPS ID:', dpsId);
    
    // Envia para a Sefin
    console.log('[EMITIR] Enviando para Sefin Nacional...');
    const resultado = await enviarParaSefin(
      signedXml,
      cert.privateKeyPem,
      cert.certificatePem,
      ambienteAtual
    );
    
    if (resultado.success) {
      console.log('[EMITIR] ✅ NFS-e emitida com sucesso!');
      
      // Tenta extrair chave de acesso
      const chaveMatch = resultado.data?.match(/<chNFSe>(\d{50})<\/chNFSe>/);
      const chaveAcesso = chaveMatch ? chaveMatch[1] : null;
      
      res.json({
        success: true,
        message: 'NFS-e emitida com sucesso',
        dpsId,
        chaveAcesso,
        ambiente: ambienteAtual,
        response: resultado.data,
        linkConsulta: chaveAcesso 
          ? `https://www.nfse.gov.br/EmissorNacional/Paginas/Publico/ConsultarNFSe.aspx?chave=${chaveAcesso}`
          : null
      });
    } else {
      console.log('[EMITIR] ❌ Erro:', resultado.data);
      res.status(400).json({
        success: false,
        error: 'Erro ao emitir NFS-e',
        dpsId,
        details: resultado.data,
        status: resultado.status
      });
    }
    
  } catch (error) {
    console.error('[EMITIR] Erro:', error.message);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============================================
// INICIALIZAÇÃO
// ============================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] NFS-e Signer rodando na porta ${PORT}`);
  console.log(`[SERVER] Ambiente: ${process.env.NFSE_AMBIENTE || 'homologacao'}`);
  
  // Tenta carregar o certificado na inicialização
  try {
    if (process.env.NFSE_CERT_BASE64) {
      loadCertificateFromEnv();
      console.log('[SERVER] ✅ Certificado carregado com sucesso');
    } else {
      console.warn('[SERVER] ⚠️ NFSE_CERT_BASE64 não configurada');
    }
  } catch (error) {
    console.error('[SERVER] ❌ Erro ao carregar certificado:', error.message);
  }
});
