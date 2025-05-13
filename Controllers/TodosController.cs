using DemoJWT.Data;
using DemoJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace DemoJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TodosController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public TodosController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult GetTodos()
        {
            var todos = _context.Todos.ToList();
            return Ok(todos);
        }

        [HttpPost]
        public IActionResult CreateTodo(Todo todo)
        {
            _context.Todos.Add(todo);
            _context.SaveChanges();
            return Ok(todo);
        }
        [HttpDelete("{id}")]
        public IActionResult DeleteTodo(int id)
        {
            var todo = _context.Todos.FirstOrDefault(t => t.Id == id);
            if (todo == null)
            {
                return NotFound(new { Message = "Todo not found" });
            }

            _context.Todos.Remove(todo);
            _context.SaveChanges();
            return Ok(new { Message = "Todo deleted successfully" });
        }

        [HttpPut("{id}")]
        public IActionResult UpdateTodo(int id, Todo updatedTodo)
        {
            if (id != updatedTodo.Id)
            {
                return BadRequest(new { Message = "ID mismatch" });
            }

            var todo = _context.Todos.FirstOrDefault(t => t.Id == id);
            if (todo == null)
            {
                return NotFound(new { Message = "Todo not found" });
            }

            todo.Title = updatedTodo.Title;
            todo.IsCompleted = updatedTodo.IsCompleted;

            _context.Todos.Update(todo);
            _context.SaveChanges();
            return Ok(todo);
        }
    }
}
