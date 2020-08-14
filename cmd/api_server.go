package main

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/zeyadyasser/dswg"
	"github.com/zeyadyasser/dswg/web"
)


func main() {
	db, _ := dswg.OpenSqliteDB("db.sqlite")
	client, _ := dswg.NewClient(db)
	api := web.APIController{
		DB: db,
		Client: *client,
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET", "POST", "OPTIONS", "PUT","PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "User-Agent", "Referrer", "Host", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  false,
		AllowOriginFunc:  func(origin string) bool { return true },
		MaxAge:           86400,
	}))

	v1 := r.Group("/api/v1")
	{
		v1.GET("/link", api.GetLinks)
		v1.POST("/link", api.AddLink)

		v1.GET("/link/:link_name", api.GetLink)
		v1.DELETE("/link/:link_name", api.RemoveLink)
		v1.PATCH("/link/:link_name", api.UpdateLink)

		v1.GET("/link/:link_name/peer", api.GetPeers)
		v1.POST("/link/:link_name/peer", api.AddPeer)

		v1.GET("/link/:link_name/peer/:peer_name", api.GetPeer)
		v1.DELETE("/link/:link_name/peer/:peer_name", api.RemovePeer)
		v1.PATCH("/link/:link_name/peer/:peer_name", api.UpdatePeer)
	}

	r.POST("/login", web.Login)
	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}
