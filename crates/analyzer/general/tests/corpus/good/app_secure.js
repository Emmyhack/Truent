// Correct handling of every shape the application-layer detectors look for.
const rateLimit = require('express-rate-limit');
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });
const wss = new WebSocket.Server({ port: 8081, verifyClient: ({ origin }) => ALLOWED.includes(origin) });
const server = new ApolloServer({ typeDefs, resolvers, introspection: false, validationRules: [depthLimit(6)] });
const USERNAME_RE = /^[a-z0-9_]{3,32}$/;

app.use('/login', rateLimit({ windowMs: 60_000, max: 10 }));

app.post('/login', async (req, res) => {
  const user = await User.findOne({ name: req.body.name });
  logger.info('login attempt', { user: req.body.name, ip: req.ip });
  if (!user || !(await bcrypt.compare(req.body.password, user.hash))) {
    logger.warn('failed login', { user: req.body.name, ip: req.ip });
    return res.sendStatus(401);
  }
  res.json({ id: user.id });
});

app.post('/users', async (req, res) => {
  const u = await User.create({ name: req.body.name, email: req.body.email });
  res.json(u);
});

app.get('/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  res.json(order);
});

app.get('/items', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  res.json(await Item.find().limit(limit));
});

app.get('/go', (req, res) => {
  const to = req.query.to;
  res.redirect(to && to.startsWith('/') ? to : '/');
});

async function transfer(from, to, amount) {
  await sequelize.transaction(async (t) => {
    from.balance -= amount;
    await from.save({ transaction: t });
    to.balance += amount;
    await to.save({ transaction: t });
  });
}

app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  logger.error('unhandled', { id, err });
  res.status(500).json({ error: 'internal error', id });
});
