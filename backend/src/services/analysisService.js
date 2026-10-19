const env=require('../config/env'),mock=require('./mockAnalysis'),mockAnalyzer=require('./mockAnalyzer'),Scan=require('../models/scan'),builder=require('./reportBuilder'),ApiError=require('../utils/ApiError'),
 {createAnalysisClient}=require('./analysisClient'),{toDbAnalysis}=require('./analysisMapper'),{toApiScan}=require('../utils/format');
exports.STAGE_MS=[500,700,800,900,800,900,1000,700,600]; // used only to animate progress while a scan is running
// Real engine (Python service) when ANALYSIS_SERVICE_URL is set; otherwise the MOCK analyzer (development only).
const client=env.analysis.url?createAnalysisClient({baseUrl:env.analysis.url,apiKey:env.analysis.apiKey,timeoutMs:env.analysis.timeoutMs}):null;
exports.usesRealEngine=()=>!!client;
exports.analyze=async url=>{
 if(client){const report=await client.analyze(url);return{analysis:toDbAnalysis(report),report}}
 if(!env.analysis.allowMock)throw new Error('Analysis service is not configured');
 return{analysis:mockAnalyzer.analyze(url),report:null};
};
const ensureReady=row=>{
 if(row.status==='Running')throw new ApiError(409,'The analysis is still running','SCAN_RUNNING');
 if(row.status==='Failed')throw new ApiError(422,row.error_message||'The analysis failed','SCAN_FAILED');
};
exports.report=async row=>{ensureReady(row);const[parts,engine]=await Promise.all([Scan.loadAnalysis(row.id),Scan.loadEngineReport(row.id)]);return builder.build(row,{...parts,engine})};
exports.detail=row=>{ensureReady(row);return{...toApiScan(row),indicators:mock.indicators}};
