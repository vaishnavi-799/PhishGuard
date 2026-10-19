require('dotenv').config();
const need=k=>{if(!process.env[k])throw new Error(`Missing required environment variable: ${k} (see .env.example)`);return process.env[k]};
const num=(k,d)=>process.env[k]?Number(process.env[k]):d;
const env={nodeEnv:process.env.NODE_ENV||'development',port:num('PORT',5000),databaseUrl:need('DATABASE_URL'),dbSsl:process.env.DATABASE_SSL==='true',
jwtSecret:need('JWT_SECRET'),jwtExpiresIn:process.env.JWT_EXPIRES_IN||'1h',bcryptRounds:num('BCRYPT_ROUNDS',12),
corsOrigins:(process.env.CORS_ORIGIN||'http://localhost:3000').split(',').map(s=>s.trim()).filter(Boolean),trustProxy:process.env.TRUST_PROXY==='true',
rateLimit:{windowMs:num('RATE_LIMIT_WINDOW_MS',900000),max:num('RATE_LIMIT_MAX',300),authMax:num('AUTH_RATE_LIMIT_MAX',10),registerMax:num('REGISTER_RATE_LIMIT_MAX',10)},
maxUploadMb:num('MAX_UPLOAD_MB',25),logLevel:process.env.LOG_LEVEL||'info',
analysis:{url:(process.env.ANALYSIS_SERVICE_URL||'').replace(/\/+$/,''),apiKey:process.env.ANALYSIS_API_KEY||'',timeoutMs:num('ANALYSIS_TIMEOUT_MS',45000),concurrency:num('ANALYSIS_CONCURRENCY',4),staleSeconds:num('ANALYSIS_STALE_SECONDS',180)}};
if(env.jwtSecret.length<32)throw new Error('JWT_SECRET must be at least 32 characters long');
env.isProd=env.nodeEnv==='production';
// Without ANALYSIS_SERVICE_URL the built-in MOCK analyzer is used (development only unless explicitly allowed)
env.analysis.allowMock=process.env.ANALYSIS_ALLOW_MOCK?process.env.ANALYSIS_ALLOW_MOCK==='true':!env.isProd;
if(!env.analysis.url&&!env.analysis.allowMock)throw new Error('ANALYSIS_SERVICE_URL is required in production (or set ANALYSIS_ALLOW_MOCK=true to accept mock analysis)');
module.exports=env;
