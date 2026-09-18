import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'

const app = express()
app.get("/", (req, res) => {
  res.send("Backend is running");
});
app.use(cors())
app.use(express.json())
const PORT = process.env.PORT || 5000
const JWT_SECRET = process.env.JWT_SECRET || 'nook-development-secret'

const productSchema = new mongoose.Schema({ name: String, description: String, price: Number, category: String, image: String, stock: Number })
const cartItemSchema = new mongoose.Schema({ productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, quantity: { type: Number, min: 1 } }, { _id: false })
const userSchema = new mongoose.Schema({ name: String, email: { type: String, unique: true }, password: String, cart: [cartItemSchema] })
const orderSchema = new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, items: [{ productId: mongoose.Schema.Types.ObjectId, name: String, price: Number, quantity: Number }], totalAmount: Number, status: { type: String, default: 'PLACED' } }, { timestamps: { createdAt: true, updatedAt: false } })
const Product = mongoose.model('Product', productSchema)
const User = mongoose.model('User', userSchema)
const Order = mongoose.model('Order', orderSchema)

const requireAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return res.status(401).json({ message: 'Authentication required' })
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = await User.findById(payload.userId)
    if (!req.user) return res.status(401).json({ message: 'User not found' })
    next()
  } catch (error) { return res.status(401).json({ message: 'Invalid or expired token' }) }
}

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email: email?.toLowerCase(), password })
  if (!user) return res.status(401).json({ message: 'Invalid email or password' })
  res.json({ token: jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '2h' }), user: { id: user._id, name: user.name, email: user.email } })
})
app.get('/api/products', requireAuth, async (req, res) => res.json(await Product.find().sort({ createdAt: -1 })))
app.get('/api/products/:id', requireAuth, async (req, res) => res.json(await Product.findById(req.params.id)))
app.get('/api/cart', requireAuth, async (req, res) => res.json(await User.findById(req.user._id).populate('cart.productId').select('cart')))
app.post('/api/cart', requireAuth, async (req, res) => res.json(await updateCart(req.user._id, req.body.productId, req.body.quantity || 1)))
app.put('/api/cart/:productId', requireAuth, async (req, res) => res.json(await updateCart(req.user._id, req.params.productId, req.body.quantity)))
app.delete('/api/cart/:productId', requireAuth, async (req, res) => res.json(await updateCart(req.user._id, req.params.productId, 0)))
async function updateCart(userId, productId, quantity) {
  const user = await User.findById(userId)
  const item = user.cart.find((entry) => entry.productId.toString() === productId)
  if (quantity < 1) user.cart = user.cart.filter((entry) => entry.productId.toString() !== productId)
  else if (item) item.quantity = quantity
  else user.cart.push({ productId, quantity })
  return (await user.save()).populate('cart.productId')
}
app.post('/api/orders', requireAuth, async (req, res) => {
  const session = await mongoose.startSession()
  try {
    let created
    await session.withTransaction(async () => {
      const user = await User.findById(req.user._id).session(session)
      if (!user.cart.length) throw Object.assign(new Error('Cart is empty'), { status: 400 })
      const ids = user.cart.map((item) => item.productId)
      const products = await Product.find({ _id: { $in: ids } }).session(session)
      const items = user.cart.map((cartItem) => {
        const product = products.find((entry) => entry._id.equals(cartItem.productId))
        if (!product) throw Object.assign(new Error('Product no longer exists'), { status: 400 })
        if (product.stock < cartItem.quantity) throw Object.assign(new Error(`${product.name} is out of stock`), { status: 409 })
        return { productId: product._id, name: product.name, price: product.price, quantity: cartItem.quantity }
      })
      const totalAmount = items.reduce((sum, item) => sum + item.price * item.quantity, 0)
      for (const item of items) await Product.updateOne({ _id: item.productId }, { $inc: { stock: -item.quantity } }, { session })
      ;[created] = await Order.create([{ userId: user._id, items, totalAmount, status: 'PLACED' }], { session })
      user.cart = []
      await user.save({ session })
    })
    res.status(201).json(created)
  } catch (error) { res.status(error.status || 500).json({ message: error.message }) } finally { await session.endSession() }
})
app.get('/api/orders', requireAuth, async (req, res) => res.json(await Order.find({ userId: req.user._id }).sort({ createdAt: -1 })))
app.get('/api/orders/:id', requireAuth, async (req, res) => res.json(await Order.findOne({ _id: req.params.id, userId: req.user._id })))

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/nook').then(async () => {
  if (await User.countDocuments() === 0) await User.create({ name: 'Alex Morgan', email: 'user@example.com', password: 'password123' })
  if (await Product.countDocuments() === 0) await Product.insertMany([
    { name: 'Wireless Mouse', description: 'Silent clicks, ergonomic grip, all-day battery life.', price: 799, category: 'Tech', stock: 18 },
    { name: 'Mechanical Keyboard', description: 'Tactile switches and a compact layout for focused work.', price: 1299, category: 'Tech', stock: 11 },
    { name: 'Studio Headphones', description: 'Immersive sound with plush memory-foam ear cushions.', price: 1999, category: 'Audio', stock: 9 },
    { name: 'Everyday T-Shirt', description: 'A breathable heavyweight cotton essential.', price: 599, category: 'Apparel', stock: 24 },
    { name: 'Runner Sneakers', description: 'Lightweight cushioning for everyday miles.', price: 2499, category: 'Footwear', stock: 7 },
  ])
  app.listen(PORT, () => console.log(`Nook API running on port ${PORT}`))
}).catch((error) => { console.error('MongoDB connection failed:', error.message); process.exit(1) })
app.get("/", (req, res) => {
  res.send("Backend is running");
});
app.get("/", (req, res) => {
  res.send("Backend is running");
});