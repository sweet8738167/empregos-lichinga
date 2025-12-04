const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Conectar ao MongoDB Atlas (GRATUITO)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://admin:password@cluster.mongodb.net/empregos-lichinga';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Conectado ao MongoDB Atlas');
}).catch(err => {
    console.error('❌ Erro ao conectar MongoDB:', err);
});

// ========== MODELOS ==========
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    phone: { type: String, default: '' },
    isEmployer: { type: Boolean, default: false },
    company: { type: String, default: '' },
    address: { type: String, default: '' },
    bio: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});

const JobSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    company: { type: String, required: true },
    employerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    employerName: { type: String, required: true },
    location: { type: String, required: true },
    salary: { type: String, default: 'A combinar' },
    vacancies: { type: Number, required: true, min: 1 },
    filled: { type: Number, default: 0 },
    requirements: { type: [String], default: [] },
    benefits: { type: [String], default: [] },
    type: { 
        type: String, 
        enum: ['Tempo Integral', 'Meio Período', 'Temporário', 'Freelance', 'Estágio'],
        default: 'Tempo Integral'
    },
    category: {
        type: String,
        enum: ['Administrativo', 'Vendas', 'Construção', 'Educação', 'Saúde', 'Transporte', 'Tecnologia', 'Agricultura', 'Outros'],
        default: 'Outros'
    },
    contactPhone: { type: String, required: true },
    contactEmail: { type: String, required: true },
    expiresAt: { type: Date, default: () => new Date(+new Date() + 30*24*60*60*1000) }, // 30 dias
    isActive: { type: Boolean, default: true },
    applicants: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        userName: String,
        userEmail: String,
        userPhone: String,
        message: String,
        appliedAt: { type: Date, default: Date.now },
        status: { 
            type: String, 
            enum: ['pending', 'reviewed', 'accepted', 'rejected'],
            default: 'pending'
        }
    }],
    createdAt: { type: Date, default: Date.now }
});

const ApplicationSchema = new mongoose.Schema({
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    userEmail: { type: String, required: true },
    userPhone: { type: String, default: '' },
    message: { type: String, default: '' },
    status: { 
        type: String, 
        enum: ['pending', 'reviewed', 'accepted', 'rejected'],
        default: 'pending'
    },
    appliedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Job = mongoose.model('Job', JobSchema);
const Application = mongoose.model('Application', ApplicationSchema);

// ========== MIDDLEWARE DE AUTENTICAÇÃO ==========
const authenticate = async (req, res, next) => {
    try {
        const userId = req.headers['user-id'];
        if (!userId) return res.status(401).json({ error: 'Não autenticado' });
        
        const user = await User.findById(userId);
        if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
        
        req.user = user;
        next();
    } catch (error) {
        res.status(500).json({ error: 'Erro de autenticação' });
    }
};

// ========== ROTAS DA API ==========

// 🟢 ROTA: Saúde do servidor
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'online',
        message: 'Emprego Lichinga API está funcionando!',
        timestamp: new Date().toISOString()
    });
});

// 🟢 ROTA: Registrar usuário
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name, phone, isEmployer, company } = req.body;
        
        // Validar dados
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
        }
        
        // Verificar se usuário já existe
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email já registrado' });
        }
        
        // Criptografar senha
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Criar novo usuário
        const user = new User({
            email,
            password: hashedPassword,
            name,
            phone: phone || '',
            isEmployer: isEmployer || false,
            company: company || ''
        });
        
        await user.save();
        
        // Não enviar a senha de volta
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json({ 
            success: true,
            message: 'Usuário criado com sucesso!',
            user: userResponse
        });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro ao criar conta' });
    }
});

// 🟢 ROTA: Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }
        
        // Buscar usuário
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Email ou senha incorretos' });
        }
        
        // Verificar senha
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Email ou senha incorretos' });
        }
        
        // Não enviar a senha de volta
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json({
            success: true,
            message: 'Login bem-sucedido!',
            user: userResponse
        });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro ao fazer login' });
    }
});

// 🟢 ROTA: Obter perfil do usuário
app.get('/api/user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar usuário' });
    }
});

// 🟢 ROTA: Publicar nova vaga (apenas empregadores)
app.post('/api/jobs', authenticate, async (req, res) => {
    try {
        if (!req.user.isEmployer) {
            return res.status(403).json({ error: 'Apenas empregadores podem publicar vagas' });
        }
        
        const jobData = {
            ...req.body,
            employerId: req.user._id,
            employerName: req.user.name,
            company: req.body.company || req.user.company,
            contactEmail: req.body.contactEmail || req.user.email,
            contactPhone: req.body.contactPhone || req.user.phone
        };
        
        const job = new Job(jobData);
        await job.save();
        
        res.status(201).json({
            success: true,
            message: 'Vaga publicada com sucesso!',
            job
        });
    } catch (error) {
        console.error('Erro ao publicar vaga:', error);
        res.status(500).json({ error: 'Erro ao publicar vaga' });
    }
});

// 🟢 ROTA: Listar todas vagas ativas
app.get('/api/jobs', async (req, res) => {
    try {
        const { category, type, search } = req.query;
        let query = { isActive: true };
        
        // Filtros
        if (category) query.category = category;
        if (type) query.type = type;
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { company: { $regex: search, $options: 'i' } },
                { location: { $regex: search, $options: 'i' } }
            ];
        }
        
        const jobs = await Job.find(query)
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json(jobs);
    } catch (error) {
        console.error('Erro ao buscar vagas:', error);
        res.status(500).json({ error: 'Erro ao buscar vagas' });
    }
});

// 🟢 ROTA: Obter vaga específica
app.get('/api/jobs/:id', async (req, res) => {
    try {
        const job = await Job.findById(req.params.id)
            .populate('employerId', 'name email phone company');
        
        if (!job) return res.status(404).json({ error: 'Vaga não encontrada' });
        
        res.json(job);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar vaga' });
    }
});

// 🟢 ROTA: Vagas por empregador
app.get('/api/jobs/employer/:employerId', authenticate, async (req, res) => {
    try {
        if (req.user._id.toString() !== req.params.employerId) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        
        const jobs = await Job.find({ employerId: req.params.employerId })
            .sort({ createdAt: -1 });
        
        res.json(jobs);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar vagas' });
    }
});

// 🟢 ROTA: Candidatar-se a vaga
app.post('/api/jobs/:id/apply', authenticate, async (req, res) => {
    try {
        const jobId = req.params.id;
        const userId = req.user._id;
        const { message } = req.body;
        
        // Verificar se vaga existe e está ativa
        const job = await Job.findById(jobId);
        if (!job || !job.isActive) {
            return res.status(404).json({ error: 'Vaga não encontrada ou encerrada' });
        }
        
        // Verificar se vagas estão disponíveis
        if (job.filled >= job.vacancies) {
            return res.status(400).json({ error: 'Todas as vagas já foram preenchidas' });
        }
        
        // Verificar se já se candidatou
        const existingApplication = await Application.findOne({ jobId, userId });
        if (existingApplication) {
            return res.status(400).json({ error: 'Você já se candidatou a esta vaga' });
        }
        
        // Criar candidatura
        const application = new Application({
            jobId,
            userId,
            userName: req.user.name,
            userEmail: req.user.email,
            userPhone: req.user.phone,
            message: message || ''
        });
        
        await application.save();
        
        // Adicionar candidato à vaga
        job.applicants.push({
            userId,
            userName: req.user.name,
            userEmail: req.user.email,
            userPhone: req.user.phone,
            message: message || '',
            status: 'pending'
        });
        
        await job.save();
        
        res.status(201).json({
            success: true,
            message: 'Candidatura enviada com sucesso!',
            application
        });
    } catch (error) {
        console.error('Erro ao candidatar-se:', error);
        res.status(500).json({ error: 'Erro ao enviar candidatura' });
    }
});

// 🟢 ROTA: Minhas candidaturas
app.get('/api/applications/my', authenticate, async (req, res) => {
    try {
        const applications = await Application.find({ userId: req.user._id })
            .populate('jobId', 'title company location')
            .sort({ appliedAt: -1 });
        
        res.json(applications);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar candidaturas' });
    }
});

// 🟢 ROTA: Candidatos de uma vaga (apenas empregador)
app.get('/api/jobs/:id/applicants', authenticate, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        
        if (!job) return res.status(404).json({ error: 'Vaga não encontrada' });
        
        // Verificar se usuário é o empregador
        if (job.employerId.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        
        res.json(job.applicants);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar candidatos' });
    }
});

// 🟢 ROTA: Atualizar status do candidato
app.put('/api/jobs/:jobId/applicants/:userId', authenticate, async (req, res) => {
    try {
        const { jobId, userId } = req.params;
        const { status } = req.body;
        
        const job = await Job.findById(jobId);
        
        if (!job) return res.status(404).json({ error: 'Vaga não encontrada' });
        
        // Verificar se usuário é o empregador
        if (job.employerId.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        
        // Atualizar status na vaga
        const applicant = job.applicants.find(app => app.userId.toString() === userId);
        if (applicant) {
            applicant.status = status;
            
            // Se aceito, incrementar vagas preenchidas
            if (status === 'accepted') {
                job.filled += 1;
            }
            
            await job.save();
        }
        
        // Atualizar na coleção de candidaturas
        await Application.findOneAndUpdate(
            { jobId, userId },
            { status },
            { new: true }
        );
        
        res.json({ success: true, message: 'Status atualizado' });
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
        res.status(500).json({ error: 'Erro ao atualizar status' });
    }
});

// 🟢 ROTA: Atualizar vaga
app.put('/api/jobs/:id', authenticate, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        
        if (!job) return res.status(404).json({ error: 'Vaga não encontrada' });
        
        // Verificar se usuário é o empregador
        if (job.employerId.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        
        Object.assign(job, req.body);
        await job.save();
        
        res.json({ success: true, message: 'Vaga atualizada', job });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar vaga' });
    }
});

// 🟢 ROTA: Fechar/Reabrir vaga
app.put('/api/jobs/:id/toggle', authenticate, async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);
        
        if (!job) return res.status(404).json({ error: 'Vaga não encontrada' });
        
        // Verificar se usuário é o empregador
        if (job.employerId.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        
        job.isActive = !job.isActive;
        await job.save();
        
        res.json({ 
            success: true, 
            message: job.isActive ? 'Vaga reaberta' : 'Vaga fechada',
            job 
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar vaga' });
    }
});

// 🟢 ROTA: Estatísticas
app.get('/api/stats', async (req, res) => {
    try {
        const totalJobs = await Job.countDocuments({ isActive: true });
        const totalUsers = await User.countDocuments();
        const totalApplications = await Application.countDocuments();
        
        // Vagas por categoria
        const jobsByCategory = await Job.aggregate([
            { $match: { isActive: true } },
            { $group: { _id: '$category', count: { $sum: 1 } } }
        ]);
        
        res.json({
            totalJobs,
            totalUsers,
            totalApplications,
            jobsByCategory
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// 🟢 ROTA: Buscar vagas por localização (Lichinga específico)
app.get('/api/jobs/location/:district', async (req, res) => {
    try {
        const district = req.params.district;
        const jobs = await Job.find({
            isActive: true,
            location: { $regex: district, $options: 'i' }
        }).sort({ createdAt: -1 });
        
        res.json(jobs);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar vagas' });
    }
});

// 🟢 ROTA: Servir arquivos estáticos
app.get('*', (req, res) => {
    res.sendFile('index.html', { root: 'public' });
});

// ========== INICIAR SERVIDOR ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`🌐 Acesse: http://localhost:${PORT}`);
    console.log(`📊 API disponível em: http://localhost:${PORT}/api/health`);
});