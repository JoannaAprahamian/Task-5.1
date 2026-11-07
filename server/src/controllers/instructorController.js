import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// ---------- Joi schemas (per-endpoint allowlists) ----------
const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(100).required()
});

// Only public fields are searchable.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(50),
  department: Joi.string().trim().max(50)
});

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Only public fields ever leave the server.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: 'Invalid input' });
    }

    // Look up by username only. The password is never part of the query.
    const instructor = await Instructor.findOne({ username: value.username })
      .select('+password');

    const ok = instructor && (await bcrypt.compare(value.password, instructor.password));
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // stripUnknown drops any key that isn't name/department (role, username, ...)
    const { error, value } = searchSchema.validate(req.query, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters' });
    }

    // Build the filter ourselves from validated strings.
    const filter = {};
    if (value.name) {
      filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    }
    if (value.department) {
      filter.department = value.department;
    }

    const instructors = await Instructor.find(filter)
      .select('name department role')
      .limit(50)
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}