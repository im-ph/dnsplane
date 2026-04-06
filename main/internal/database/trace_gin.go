package database

import (
	"context"
	"runtime"
	"sync"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GinContextKey 在 context / GORM Statement 中挂载 *gin.Context 的键（与 WithContext 一致）
const GinContextKey = "gin_context"

var traceGinByGoroutine sync.Map // goroutine id -> *gin.Context

func currentGoroutineID() uint64 {
	var buf [128]byte
	n := runtime.Stack(buf[:], false)
	const prefix = "goroutine "
	if n <= len(prefix) {
		return 0
	}
	if string(buf[:len(prefix)]) != prefix {
		return 0
	}
	var id uint64
	i := len(prefix)
	for i < n && buf[i] >= '0' && buf[i] <= '9' {
		id = id*10 + uint64(buf[i]-'0')
		i++
	}
	return id
}

// BindRequestGinForDBTrace 将当前 HTTP 处理 goroutine 与 gin.Context 绑定，
// 供裸用 database.DB / LogDB 的 GORM 回调注入 GinContextKey，从而写入 db_queries。
// 应在 RequestTrace 中于 c.Next() 之前 defer cleanup()。
func BindRequestGinForDBTrace(c *gin.Context) (cleanup func()) {
	id := currentGoroutineID()
	if id == 0 {
		return func() {}
	}
	traceGinByGoroutine.Store(id, c)
	return func() { traceGinByGoroutine.Delete(id) }
}

func injectGinIntoDBStatement(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	ctx := db.Statement.Context
	if ctx != nil {
		if _, ok := ctx.Value(GinContextKey).(*gin.Context); ok {
			return
		}
	} else {
		ctx = context.Background()
	}
	id := currentGoroutineID()
	if id == 0 {
		return
	}
	v, ok := traceGinByGoroutine.Load(id)
	if !ok {
		return
	}
	gc, ok := v.(*gin.Context)
	if !ok || gc == nil {
		return
	}
	db.Statement.Context = context.WithValue(ctx, GinContextKey, gc)
}
