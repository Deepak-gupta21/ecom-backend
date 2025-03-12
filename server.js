require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();




// **Middleware to Verify Token**
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "Access Denied" });

  jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid Token" });
    req.user = decoded;
    next();
  });
};


// **Middleware to Verify Admin**
const verifyAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Extract token
    if (!token) {
        return res.status(401).json({ message: "Access denied! No token provided." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
        if (decoded.role !== "admin") {
            return res.status(403).json({ message: "Access forbidden! Admins only." });
        }
        req.user = decoded; // Attach decoded user to request
        next(); // Continue to the route
    } catch (error) {
        res.status(401).json({ message: "Invalid token!" });
    }
};


// **Role-Based Middleware**
const authorizeRoles = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    next();
  };
};
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Connection Failed:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String,
});

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  stock: Number,
});

const Product = mongoose.model("Product", productSchema);

const User = mongoose.model("User", userSchema);

// Generate Token
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
};

// **Register Route**
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  const existingUser = await User.findOne({ username });

  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword, role });

  await newUser.save();
  res.json({ message: "User registered successfully!" });
});

app.post("/addProduct", verifyAdmin, async (req, res) => {
  const { name, price, stock } = req.body;

  // Check if product already exists
  const existingProduct = await Product.findOne({ name });

  if (existingProduct) {
    return res.status(400).json({ message: "Product already exists!" });
  }

  // Create and save new product
  const newProduct = new Product({ name, price, stock });

  try {
    await newProduct.save();
    res.status(201).json({ message: "Product added successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Failed to add product", error });
  }
});


// ** get Product Route**
app.get("/getProduct", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch products", error });
  }
});


// **Login Route**
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: "Invalid Credentials" });
  }

  const token = generateToken(user);

  res.json({
    token,
    role: user.role,
    message: "Login successful",
  });
});





// **Protected Routes**
app.get(
  "/user-dashboard",
  verifyToken,
  authorizeRoles(["user"]),
  (req, res) => {
    res.json({ message: "Welcome User!" });
  }
);

app.get(
  "/admin-dashboard",
  verifyToken,
  authorizeRoles(["admin"]),
  (req, res) => {
    res.json({ message: "Welcome Admin!" });
  }
);

// **Logout Route (Frontend should just remove token)**
app.post("/logout", (req, res) => {
  res.json({ message: "Logout successful" });
});

app.listen(5000, () => console.log("Server running on port 5000"));
