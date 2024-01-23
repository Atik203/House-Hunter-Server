require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.okdmlp6.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  const verifyToken = async (req, res, next) => {
    const token = req.cookies?.token;

    if (!token) {
      return res.status(401).send({ message: "not authorized" });
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).send({ message: "not authorized" });
      }
      req.user = decoded;
    });
    next();
  };

  const userCollection = client.db("House-Hunter").collection("Users");
  const houseCollection = client.db("House-Hunter").collection("Houses");

  try {
    app.post("/register", async (req, res) => {
      try {
        const user = req.body;
        const query = { email: user.email };

        const isExist = await userCollection.findOne(query);
        if (isExist) {
          return res.send({ message: "user exists", insertedId: null });
        }

        const hashedPassword = await bcrypt.hash(user.password, 10);
        user.password = hashedPassword;

        const result = await userCollection.insertOne(user);

        const token = jwt.sign(
          { userId: result.insertedId },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );

        res.cookie("token", token, { httpOnly: true });
        res.send(result);
      } catch (error) {
        console.error(error);
        return res.send({ message: "error", insertedId: undefined });
      }
    });

    app.post("/userLogin", async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.send({ message: "User not found", token: null });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res.send({ message: "Invalid password", token: null });
        }
        const token = jwt.sign(
          { userId: user._id },
          process.env.ACCESS_TOKEN_SECRET,
          {
            expiresIn: "1h",
          }
        );
        res.cookie("token", token, { httpOnly: true });
        res.send({ message: "Login successful", token });
      } catch (error) {
        console.error(error);
        return res.send({ message: "Error", token: null });
      }
    });

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1hr",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production" ? true : false,
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });
    app.post("/logout", async (req, res) => {
      const user = req.body;
      res
        .clearCookie("token", {
          maxAge: 0,
          secure: process.env.NODE_ENV === "production" ? true : false,
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    app.get("/userByEmail/:email", async (req, res) => {
      try {
        const userEmail = req.params.email;
        console.log(userEmail);
        const user = await userCollection.findOne({ email: userEmail });

        if (!user) {
          return res
            .status(404)
            .send({ success: false, message: "User not found" });
        }
        console.log(user);
        res.send(user);
      } catch (error) {
        console.error(error);
        res
          .status(500)
          .send({ success: false, message: "Internal Server Error" });
      }
    });

    app.post("/houses", async (req, res) => {
      const house = req.body;
      console.log(house);
      const result = await houseCollection.insertOne(house);
      res.send(result);
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server is running");
});

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
});
