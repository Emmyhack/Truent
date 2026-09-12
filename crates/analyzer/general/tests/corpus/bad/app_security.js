// EXPECT: gen_mass_assignment
// EXPECT: gen_upload_unvalidated
// EXPECT: gen_error_detail_exposed
// EXPECT: gen_log_sensitive_data
// EXPECT: gen_regex_dos
// EXPECT: gen_graphql_unrestricted
// EXPECT: gen_websocket_no_origin_check
// EXPECT: gen_non_atomic_multi_write
// EXPECT: gen_object_level_auth_missing
// EXPECT: gen_unbounded_query_limit
// EXPECT: gen_open_redirect
// EXPECT: gen_log_injection
// EXPECT: gen_missing_rate_limit
const upload = multer({ dest: 'uploads/' });
const wss = new WebSocket.Server({ port: 8081 });
const server = new ApolloServer({ typeDefs, resolvers });
const USERNAME_RE = /^(\w+\s?)*$/;

app.post('/login', async (req, res) => {
  const user = await User.findOne({ name: req.body.name });
  console.log('login attempt', req.body.name, req.body.password);
  res.json(user);
});

app.post('/users', async (req, res) => {
  const u = await User.create(req.body);
  res.json(u);
});

app.get('/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

app.get('/items', async (req, res) => {
  const limit = parseInt(req.query.limit);
  res.json(await Item.find().limit(limit));
});

app.get('/go', (req, res) => {
  const to = req.query.to;
  res.redirect(to);
});

app.post('/comment', (req, res) => {
  const text = req.body.text;
  logger.info('comment posted: ' + text);
  res.sendStatus(204);
});

async function transfer(from, to, amount) {
  from.balance -= amount;
  await from.save();
  to.balance += amount;
  await to.save();
}

app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});
