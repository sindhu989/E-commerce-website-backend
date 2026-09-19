import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'

const app = express()

// ===============================
// CORS CONFIGURATION
// ===============================

const allowedOrigins = (process.env.CORS_ORIGINS ||
  'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests without an origin (Postman, server-to-server, etc.)
      if (!origin) {
        return callback(null, true)
      }

      // Allow your Vercel frontend
      if (allowedOrigins.includes(origin)) {
        return callback(null, true)
      }

      return callback(new Error('CORS origin not allowed'))
    },

    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],

    allowedHeaders: ['Content-Type', 'Authorization'],

    credentials: true,
  })
)

// JSON body parser
app.use(express.json())

// ===============================
// ENVIRONMENT VARIABLES
// ===============================

const PORT = process.env.PORT || 5000

const JWT_SECRET = process.env.JWT_SECRET || (
  process.env.NODE_ENV === 'production'
    ? (() => { throw new Error('JWT_SECRET is required in production') })()
    : 'nook-development-secret'
)
const MONGO_URI = process.env.MONGO_URI || (
  process.env.NODE_ENV === 'production'
    ? (() => { throw new Error('MONGO_URI is required in production') })()
    : 'mongodb://127.0.0.1:27017/nook'
)

// ===============================
// DATABASE SCHEMAS
// ===============================

const productSchema = new mongoose.Schema(
  {
    name: String,
    description: String,
    price: Number,
    category: String,
    image: String,
    stock: Number,
  },
  {
    timestamps: true,
  }
)

const cartItemSchema = new mongoose.Schema(
  {
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
    },

    quantity: {
      type: Number,
      min: 1,
    },
  },
  {
    _id: false,
  }
)

const userSchema = new mongoose.Schema({
  name: String,

  email: {
    type: String,
    unique: true,
  },

  password: {
    type: String,
    required: true,
    minlength: 8,
  },

  cart: [cartItemSchema],
})

const orderSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,

    items: [
      {
        productId: mongoose.Schema.Types.ObjectId,
        name: String,
        price: Number,
        quantity: Number,
      },
    ],

    totalAmount: Number,

    status: {
      type: String,
      default: 'PLACED',
    },
  },
  {
    timestamps: {
      createdAt: true,
      updatedAt: false,
    },
  }
)

// ===============================
// MODELS
// ===============================

const Product = mongoose.model('Product', productSchema)
const User = mongoose.model('User', userSchema)
const Order = mongoose.model('Order', orderSchema)

// ===============================
// ROOT / HEALTH CHECK
// ===============================

app.get('/', (req, res) => {
  res.send('Backend is running')
})

// ===============================
// AUTHENTICATION MIDDLEWARE
// ===============================

const requireAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace(
      'Bearer ',
      ''
    )

    if (!token) {
      return res.status(401).json({
        message: 'Authentication required',
      })
    }

    const payload = jwt.verify(token, JWT_SECRET)

    req.user = await User.findById(payload.userId)

    if (!req.user) {
      return res.status(401).json({
        message: 'User not found',
      })
    }

    next()
  } catch (error) {
    return res.status(401).json({
      message: 'Invalid or expired token',
    })
  }
}

// ===============================
// LOGIN
// ===============================

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase()
    const password = req.body.password

    if (!email || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({
        message: 'A valid email and password are required',
      })
    }

    const user = await User.findOne({ email })
    const passwordMatches = user && (
      user.password.startsWith('$2a$') ||
      user.password.startsWith('$2b$') ||
      user.password.startsWith('$2y$')
        ? await bcrypt.compare(password, user.password)
        : user.password === password
    )

    if (!user || !passwordMatches) {
      return res.status(401).json({
        message: 'Invalid email or password',
      })
    }

    if (!user.password.startsWith('$2')) {
      user.password = await bcrypt.hash(password, 12)
      await user.save()
    }

    const token = jwt.sign(
      {
        userId: user._id,
      },
      JWT_SECRET,
      {
        expiresIn: '2h',
      }
    )

    res.json({
      token,

      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    })
  } catch (error) {
    console.error('Login error:', error)

    res.status(500).json({
      message: 'Server error',
    })
  }
})

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = req.body.name?.trim()
    const email = req.body.email?.trim().toLowerCase()
    const password = req.body.password

    if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Name and a valid email are required' })
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' })
    }
    if (await User.exists({ email })) {
      return res.status(409).json({ message: 'An account with this email already exists' })
    }

    const user = await User.create({
      name,
      email,
      password: await bcrypt.hash(password, 12),
      cart: [],
    })

    res.status(201).json({
      user: { id: user._id, name: user.name, email: user.email },
    })
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ message: 'Unable to create account' })
  }
})

// ===============================
// PRODUCTS
// ===============================

app.get('/api/products', requireAuth, async (req, res) => {
  try {
    const products = await Product.find().sort({
      createdAt: -1,
    })

    res.json(products)
  } catch (error) {
    res.status(500).json({
      message: error.message,
    })
  }
})

app.get(
  '/api/products/:id',
  requireAuth,
  async (req, res) => {
    try {
      const product = await Product.findById(
        req.params.id
      )

      if (!product) {
        return res.status(404).json({
          message: 'Product not found',
        })
      }

      res.json(product)
    } catch (error) {
      res.status(500).json({
        message: error.message,
      })
    }
  }
)

// ===============================
// CART
// ===============================

app.get('/api/cart', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('cart.productId')
      .select('cart')

    res.json(user)
  } catch (error) {
    res.status(500).json({
      message: error.message,
    })
  }
})

app.post('/api/cart', requireAuth, async (req, res) => {
  try {
    const result = await updateCart(
      req.user._id,
      req.body.productId,
      req.body.quantity || 1
    )

    res.json(result)
  } catch (error) {
    res.status(500).json({
      message: error.message,
    })
  }
})

app.put(
  '/api/cart/:productId',
  requireAuth,
  async (req, res) => {
    try {
      const result = await updateCart(
        req.user._id,
        req.params.productId,
        req.body.quantity
      )

      res.json(result)
    } catch (error) {
      res.status(500).json({
        message: error.message,
      })
    }
  }
)

app.delete(
  '/api/cart/:productId',
  requireAuth,
  async (req, res) => {
    try {
      const result = await updateCart(
        req.user._id,
        req.params.productId,
        0
      )

      res.json(result)
    } catch (error) {
      res.status(500).json({
        message: error.message,
      })
    }
  }
)

// ===============================
// UPDATE CART FUNCTION
// ===============================

async function updateCart(
  userId,
  productId,
  quantity
) {
  const user = await User.findById(userId)

  if (!user) {
    throw new Error('User not found')
  }

  const item = user.cart.find(
    (entry) =>
      entry.productId.toString() === productId
  )

  if (quantity < 1) {
    user.cart = user.cart.filter(
      (entry) =>
        entry.productId.toString() !== productId
    )
  } else if (item) {
    item.quantity = quantity
  } else {
    user.cart.push({
      productId,
      quantity,
    })
  }

  const savedUser = await user.save()

  return savedUser.populate('cart.productId')
}

// ===============================
// CREATE ORDER
// ===============================

app.post('/api/orders', requireAuth, async (req, res) => {
  const session = await mongoose.startSession()

  try {
    let created

    await session.withTransaction(async () => {
      const user = await User.findById(
        req.user._id
      ).session(session)

      if (!user.cart.length) {
        throw Object.assign(
          new Error('Cart is empty'),
          {
            status: 400,
          }
        )
      }

      const ids = user.cart.map(
        (item) => item.productId
      )

      const products = await Product.find({
        _id: {
          $in: ids,
        },
      }).session(session)

      const items = user.cart.map((cartItem) => {
        const product = products.find((entry) =>
          entry._id.equals(cartItem.productId)
        )

        if (!product) {
          throw Object.assign(
            new Error(
              'Product no longer exists'
            ),
            {
              status: 400,
            }
          )
        }

        if (
          product.stock <
          cartItem.quantity
        ) {
          throw Object.assign(
            new Error(
              `${product.name} is out of stock`
            ),
            {
              status: 409,
            }
          )
        }

        return {
          productId: product._id,
          name: product.name,
          price: product.price,
          quantity: cartItem.quantity,
        }
      })

      const totalAmount = items.reduce(
        (sum, item) =>
          sum +
          item.price * item.quantity,
        0
      )

      for (const item of items) {
        await Product.updateOne(
          {
            _id: item.productId,
          },
          {
            $inc: {
              stock: -item.quantity,
            },
          },
          {
            session,
          }
        )
      }

      ;[created] = await Order.create(
        [
          {
            userId: user._id,
            items,
            totalAmount,
            status: 'PLACED',
          },
        ],
        {
          session,
        }
      )

      user.cart = []

      await user.save({
        session,
      })
    })

    res.status(201).json(created)
  } catch (error) {
    res.status(error.status || 500).json({
      message: error.message,
    })
  } finally {
    await session.endSession()
  }
})

// ===============================
// GET ORDERS
// ===============================

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({
      userId: req.user._id,
    }).sort({
      createdAt: -1,
    })

    res.json(orders)
  } catch (error) {
    res.status(500).json({
      message: error.message,
    })
  }
})

// ===============================
// GET SINGLE ORDER
// ===============================

app.get(
  '/api/orders/:id',
  requireAuth,
  async (req, res) => {
    try {
      const order = await Order.findOne({
        _id: req.params.id,
        userId: req.user._id,
      })

      if (!order) {
        return res.status(404).json({
          message: 'Order not found',
        })
      }

      res.json(order)
    } catch (error) {
      res.status(500).json({
        message: error.message,
      })
    }
  }
)

// ===============================
// MONGODB CONNECTION
// ===============================

mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected')

    // Create default user
    if ((await User.countDocuments()) === 0) {
      await User.create({
        name: 'Alex Morgan',
        email: 'user@example.com',
        password: await bcrypt.hash('password123', 12),
        cart: [],
      })

      console.log('Default user created')
    }

    // Create default products
    if ((await Product.countDocuments()) === 0) {
      await Product.insertMany([
        {
          name: 'Wireless Mouse',
          description:
            'Silent clicks, ergonomic grip, all-day battery life.',
          price: 799,
          category: 'Tech',
          stock: 18,
        },

        {
          name: 'Mechanical Keyboard',
          description:
            'Tactile switches and a compact layout for focused work.',
          price: 1299,
          category: 'Tech',
          stock: 11,
        },

        {
          name: 'Studio Headphones',
          description:
            'Immersive sound with plush memory-foam ear cushions.',
          price: 1999,
          category: 'Audio',
          stock: 9,
        },

        {
          name: 'Everyday T-Shirt',
          description:
            'A breathable heavyweight cotton essential.',
          price: 599,
          category: 'Apparel',
          stock: 24,
        },

        {
          name: 'Runner Sneakers',
          description:
            'Lightweight cushioning for everyday miles.',
          price: 2499,
          category: 'Footwear',
          stock: 7,
        },
      ])

      console.log('Default products created')
    }

    // ===============================
    // START SERVER
    // ===============================

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Nook API running on port ${PORT}`
        )
      }
    )
  })
  .catch((error) => {
    console.error(
      'MongoDB connection failed:',
      error.message
    )

    process.exit(1)
  })