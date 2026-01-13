/**
 * Pear视频解析 Cloudflare Worker (代理工具版)
 * 
 * 使用方式：
 * GET /?id=movieId&sign=xxx&t=timestamp              - 电影解析
 * GET /?id=animeId&type=anime&sign=xxx&t=timestamp   - 动漫解析
 * GET /?url=原始URL&sign=xxx&t=timestamp
 * 
 * sign生成: 
 * 
 * 返回：视频播放详情JSON
 */
