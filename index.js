require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(express.json()); // para parsing de JSON

// Para o webhook do Stripe precisamos do raw body
app.use("/webhook-stripe", bodyParser.raw({ type: "application/json" }));

// Configuração da conexão com o MySQL (usando pool)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : false,
});

// Testar conexão e criar tabela "usuarios" se não existir
async function initDb() {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query("SELECT NOW() AS now");
    console.log(`Conexão com banco de dados estabelecida: ${rows[0].now}`);

    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        nome VARCHAR(255),
        stripe_customer_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'inativo',
        plano VARCHAR(100),
        api_key VARCHAR(255),
        data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_assinatura TIMESTAMP DEFAULT NULL,
        data_renovacao TIMESTAMP DEFAULT NULL,
        data_modificacao TIMESTAMP DEFAULT NULL
      )
    `;
    await connection.query(createTableQuery);
    console.log("Tabela de usuários verificada ou criada com sucesso");
    connection.release();
  } catch (error) {
    console.error("Erro ao conectar ao banco de dados: ", error);
  }
}
initDb();

// Função para gerar API Key usando o módulo crypto
function generateApiKey() {
  return crypto.randomBytes(32).toString("base64url");
}

// Middleware para verificar a API Key (se for necessário proteger endpoints)
async function verifyApiKey(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ success: false, error: "API key não fornecida" });
  }
  const apiKey = authHeader.split(" ")[1];
  try {
    const [rows] = await pool.query(
      "SELECT * FROM usuarios WHERE api_key = ?",
      [apiKey]
    );
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ success: false, error: "API key inválida" });
    }
    req.user = rows[0];
    next();
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
}

// --------------------- ROTAS DA API ---------------------

// Retornar a chave pública do Stripe
app.get("/api/config", (req, res) => {
  res.json({
    success: true,
    stripePublicKey: process.env.STRIPE_PUBLISHABLE_KEY,
  });
});

// Criar ou buscar um cliente no Stripe
app.post("/api/create-customer", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: "Email não fornecido" });
    }
    const customers = await stripe.customers.list({ email, limit: 1 });
    let customer;
    if (customers.data.length > 0) {
      customer = customers.data[0];
      console.log(`Cliente existente encontrado: ${customer.id}`);
    } else {
      customer = await stripe.customers.create({
        email,
        description: "Cliente PayoutHub",
      });
      console.log(`Novo cliente criado: ${customer.id}`);
    }
    res.json({ success: true, customerId: customer.id });
  } catch (error) {
    console.error("Erro ao criar cliente:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verificar se o usuário existe no banco de dados
app.post("/api/verify-user", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: "Email não fornecido" });
    }
    const [rows] = await pool.query(
      "SELECT email, stripe_customer_id, status FROM usuarios WHERE email = ?",
      [email]
    );
    if (rows.length > 0) {
      res.json({
        success: true,
        exists: true,
        status: rows[0].status,
        customerId: rows[0].stripe_customer_id,
      });
    } else {
      res.json({ success: true, exists: false });
    }
  } catch (error) {
    console.error("Erro ao verificar usuário:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Obter informações do usuário
app.get("/api/user-info", async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: "Email não fornecido" });
    }
    const [rows] = await pool.query(
      "SELECT email, nome, status, plano, data_assinatura, data_renovacao FROM usuarios WHERE email = ?",
      [email]
    );
    if (rows.length > 0) {
      const user = rows[0];
      res.json({
        success: true,
        user: {
          email: user.email,
          nome: user.nome || user.email.split("@")[0],
          status: user.status,
          plano: user.plano,
          dataAssinatura: user.data_assinatura,
          dataRenovacao: user.data_renovacao,
        },
      });
    } else {
      res.json({ success: false, error: "Usuário não encontrado" });
    }
  } catch (error) {
    console.error("Erro ao obter informações do usuário:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Obter a API Key do usuário
app.get("/api/user/api-key", async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: "Email não fornecido" });
    }
    const [rows] = await pool.query(
      "SELECT api_key FROM usuarios WHERE email = ?",
      [email]
    );
    if (rows.length > 0 && rows[0].api_key) {
      res.json({ success: true, apiKey: rows[0].api_key });
    } else {
      res.json({ success: false, error: "API Key não encontrada" });
    }
  } catch (error) {
    console.error("Erro ao obter API Key:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Obter detalhes de assinatura do Stripe
app.get("/api/subscription/:customerId", async (req, res) => {
  try {
    const customerId = req.params.customerId;
    if (!customerId) {
      return res
        .status(400)
        .json({ success: false, error: "ID do cliente não fornecido" });
    }
    const subscriptions = await stripe.subscriptions.list({
      customer: customerId,
      status: "active",
      limit: 1,
    });
    if (subscriptions.data.length > 0) {
      const subscription = subscriptions.data[0];
      const plan = subscription.items.data[0].plan;
      const product = await stripe.products.retrieve(plan.product);
      res.json({
        success: true,
        subscription: {
          id: subscription.id,
          status: subscription.status,
          plan: product.name,
          current_period_start: subscription.current_period_start,
          current_period_end: subscription.current_period_end,
          cancel_at_period_end: subscription.cancel_at_period_end,
        },
      });
    } else {
      res.json({ success: true, subscription: null });
    }
  } catch (error) {
    console.error("Erro ao obter detalhes da assinatura:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Criar sessão de checkout para assinatura via Stripe
app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const { planId, email } = req.body;
    if (!planId) {
      return res
        .status(400)
        .json({ success: false, error: "Plano não especificado" });
    }
    let amount, interval, intervalCount, planName;
    if (planId === "trimestral") {
      amount = 7500; // em centavos
      interval = "month";
      intervalCount = 3;
      planName = "Plano Trimestral";
    } else if (planId === "anual") {
      amount = 18000; // em centavos
      interval = "year";
      intervalCount = 1;
      planName = "Plano Anual";
    } else {
      return res.status(400).json({ success: false, error: "Plano inválido" });
    }
    // Criar produto
    const product = await stripe.products.create({
      name: planName,
      description: `Assinatura ${planName} do PayoutHub`,
    });
    // Criar preço para o produto
    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: amount,
      currency: "brl",
      recurring: {
        interval,
        interval_count: intervalCount,
      },
    });
    // Configurar dados da sessão de checkout
    let checkoutData = {
      success_url: `${req.protocol}://${req.get(
        "host"
      )}/checkout-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get("host")}/`,
      mode: "subscription",
      line_items: [{ price: price.id, quantity: 1 }],
      metadata: { plan: planName },
    };
    if (email) {
      const customers = await stripe.customers.list({ email, limit: 1 });
      let customer;
      if (customers.data.length > 0) {
        customer = customers.data[0];
      } else {
        customer = await stripe.customers.create({
          email,
          description: "Cliente PayoutHub",
        });
      }
      checkoutData.customer = customer.id;
    }
    const session = await stripe.checkout.sessions.create(checkoutData);
    res.json({ success: true, sessionId: session.id });
  } catch (error) {
    console.error("Erro ao criar sessão de checkout:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Webhook do Stripe para tratar eventos como checkout, pagamento e cancelamento de assinatura
app.post("/webhook-stripe", (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Erro no webhook:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Disparar funções de tratamento conforme o tipo do evento
  switch (event.type) {
    case "checkout.session.completed":
      handleCheckoutSessionCompleted(event.data.object);
      break;
    case "invoice.paid":
      handleInvoicePaid(event.data.object);
      break;
    case "customer.subscription.deleted":
      handleSubscriptionCanceled(event.data.object);
      break;
    default:
      console.log(`Evento não tratado: ${event.type}`);
  }

  res.json({ status: "success" });
});

// Função para tratar checkout finalizado com sucesso
async function handleCheckoutSessionCompleted(session) {
  try {
    const email = session.customer_details && session.customer_details.email;
    const customerId = session.customer;
    const planName = session.metadata ? session.metadata.plan : "desconhecido";
    if (!email) {
      console.log("Email não encontrado na sessão de checkout");
      return;
    }
    const [rows] = await pool.query(
      "SELECT email, api_key FROM usuarios WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      const apiKey = generateApiKey();
      await pool.query(
        "INSERT INTO usuarios (email, stripe_customer_id, status, plano, api_key, data_assinatura, data_renovacao) VALUES (?, ?, 'ativo', ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 3 MONTH))",
        [email, customerId, planName, apiKey]
      );
    } else {
      let apiKey = rows[0].api_key;
      if (!apiKey) {
        apiKey = generateApiKey();
      }
      await pool.query(
        "UPDATE usuarios SET stripe_customer_id = ?, status = 'ativo', plano = ?, api_key = ?, data_assinatura = NOW(), data_renovacao = DATE_ADD(NOW(), INTERVAL 3 MONTH) WHERE email = ?",
        [customerId, planName, apiKey, email]
      );
    }
    console.log(`Usuário ${email} processado com sucesso após checkout`);
  } catch (error) {
    console.error("Erro ao processar checkout:", error);
  }
}

// Função para tratar fatura paga
async function handleInvoicePaid(invoice) {
  try {
    const subscriptionId = invoice.subscription;
    const customerId = invoice.customer;
    if (!subscriptionId || !customerId) return;

    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const customer = await stripe.customers.retrieve(customerId);
    const email = customer.email;
    let planName, intervalClause;
    const plan = subscription.items.data[0].plan;
    if (plan.interval === "year") {
      planName = "Plano Anual";
      intervalClause = "DATE_ADD(NOW(), INTERVAL 1 YEAR)";
    } else if (plan.interval === "month" && plan.interval_count === 3) {
      planName = "Plano Trimestral";
      intervalClause = "DATE_ADD(NOW(), INTERVAL 3 MONTH)";
    } else {
      planName = "Plano Personalizado";
      intervalClause = "DATE_ADD(NOW(), INTERVAL 1 MONTH)";
    }
    await pool.query(
      `UPDATE usuarios SET status = 'ativo', plano = ?, data_renovacao = ${intervalClause}, data_modificacao = NOW() WHERE email = ?`,
      [planName, email]
    );
    console.log(`Usuário ${email} atualizado após pagamento da fatura`);
  } catch (error) {
    console.error("Erro ao processar invoice paga:", error);
  }
}

// Função para tratar cancelamento da assinatura
async function handleSubscriptionCanceled(subscription) {
  try {
    const customerId = subscription.customer;
    if (!customerId) return;
    const customer = await stripe.customers.retrieve(customerId);
    const email = customer.email;
    await pool.query(
      "UPDATE usuarios SET status = 'inativo', data_modificacao = NOW() WHERE email = ?",
      [email]
    );
    console.log(`Assinatura do usuário ${email} cancelada`);
  } catch (error) {
    console.error("Erro ao processar cancelamento da assinatura:", error);
  }
}

// Tratamento de encerramento da aplicação (fechando conexões com o banco)
process.on("SIGINT", () => {
  console.log("Fechando conexões com o banco de dados...");
  pool.end().then(() => {
    console.log("Conexões fechadas com sucesso");
    process.exit(0);
  });
});
process.on("SIGTERM", () => {
  console.log("Fechando conexões com o banco de dados...");
  pool.end().then(() => {
    console.log("Conexões fechadas com sucesso");
    process.exit(0);
  });
});

// Inicializar o servidor
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API iniciada na porta ${port}`);
});
