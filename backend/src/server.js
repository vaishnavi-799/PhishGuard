const env=require('./config/env'),app=require('./app'),db=require('./config/db'),logger=require('./utils/logger');
(async()=>{try{await db.query('select 1');logger.info('PostgreSQL connected');
 const stale=await require('./models/scan').failStale(env.analysis.staleSeconds);if(stale)logger.warn(`Marked ${stale} interrupted scan(s) as failed`); // in-process jobs do not survive a restart
 if(!env.analysis.url)logger.warn('ANALYSIS_SERVICE_URL not set: using the MOCK analyzer');
 const server=app.listen(env.port,()=>logger.info(`PhishGuard API listening on http://localhost:${env.port} (${env.nodeEnv})`));
 const stop=()=>server.close(()=>db.pool.end().then(()=>process.exit(0)));process.on('SIGINT',stop);process.on('SIGTERM',stop);
}catch(e){logger.error('Startup failed: '+e.message);process.exit(1)}})();
process.on('unhandledRejection',e=>logger.error('unhandledRejection',{err:String(e)}));
